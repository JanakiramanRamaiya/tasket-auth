import { Controller, Get, Next, Req, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as passport from 'passport';
import { AuthService } from './auth.service';
import { OAuthService } from '../oauth/oauth.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private oauthService: OAuthService,
    private config: ConfigService,
  ) {}

  @Get('google')
  googleLogin(@Req() req: any, @Res() res: any, @Next() next: any) {
    // Explicitly pass the state query param as the OAuth state so it is
    // echoed back by Google in the callback (needed for MCP PKCE flow).
    const state = req.query?.state as string | undefined;
    passport.authenticate('google', {
      scope: ['email', 'profile'],
      ...(state ? { state } : {}),
    } as any)(req, res, next);
  }

  @Get('google/callback')
  googleCallback(@Req() req: any, @Res() res: any, @Next() next: any) {
    passport.authenticate('google', { session: false }, async (err: any, profile: any) => {
      if (err || !profile) {
        return res.status(500).send('Authentication failed. Please try again.');
      }

      try {
        const user = await this.authService.findOrCreateFromGoogle(profile);
        const mcpStateId: string | null = profile.mcpStateId;

        if (mcpStateId) {
          // MCP OAuth 2.1 flow — issue auth code and redirect to MCP client
          const mcpState = this.oauthService.getMcpAuthState(mcpStateId);
          if (!mcpState) {
            return res.status(400).send('OAuth state expired or invalid. Please start the login again.');
          }
          this.oauthService.clearMcpAuthState(mcpStateId);
          const code = await this.oauthService.issueMcpAuthCode(user.id, mcpState);
          const redirect = new URL(mcpState.redirectUri);
          redirect.searchParams.set('code', code);
          if (mcpState.clientState) redirect.searchParams.set('state', mcpState.clientState);
          return res.redirect(redirect.toString());
        }

        // Frontend flow — issue JWT and redirect back to frontend
        const token = await this.oauthService.generateAccessToken(user);
        const frontendUrl = this.config.get<string>('FRONTEND_URL');
        return res.redirect(`${frontendUrl}/auth/callback?token=${token}`);
      } catch (e: any) {
        console.error('Google callback error:', e);
        return res.status(500).send(`Authentication error: ${e.message}`);
      }
    })(req, res, next);
  }
}
