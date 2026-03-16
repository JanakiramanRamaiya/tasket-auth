import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
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
  @UseGuards(AuthGuard('google'))
  googleLogin() {
    // Passport redirects to Google — state param flows through automatically
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: any, @Res() res: any) {
    const profile = req.user;
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
  }
}
