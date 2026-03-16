import { Controller, Get, Post, Body, Query, Res } from '@nestjs/common';
import { OAuthService } from './oauth.service';
import { ConfigService } from '@nestjs/config';

@Controller()
export class OAuthController {
  constructor(private oauthService: OAuthService, private config: ConfigService) {}

  // ── Discovery ──────────────────────────────────────────────────────

  @Get('.well-known/oauth-authorization-server')
  getAuthServerMetadata() {
    return this.oauthService.getAuthServerMetadata();
  }

  @Get('.well-known/oauth-protected-resource/mcp')
  getProtectedResourceMetadata() {
    return this.oauthService.getProtectedResourceMetadata();
  }

  @Get('.well-known/jwks.json')
  getJwks() {
    return this.oauthService.getJwks();
  }

  // ── Dynamic Client Registration ────────────────────────────────────

  @Post('oauth/register')
  register(@Body() body: any) {
    return this.oauthService.registerClient({
      client_name: body.client_name,
      redirect_uris: body.redirect_uris ?? [],
      grant_types: body.grant_types,
      response_types: body.response_types,
    });
  }

  // ── Authorization (MCP entry point) ───────────────────────────────

  @Get('oauth/authorize')
  authorize(
    @Query('client_id') clientId: string,
    @Query('code_challenge') codeChallenge: string,
    @Query('code_challenge_method') codeChallengeMethod = 'S256',
    @Query('redirect_uri') redirectUri: string,
    @Query('state') clientState = '',
    @Query('scope') scope = 'read write',
    @Res() res: any,
  ) {
    const mcpStateId = this.oauthService.storeMcpAuthState({
      clientId, codeChallenge, codeChallengeMethod,
      redirectUri, clientState,
      scopes: scope.split(' ').filter(Boolean),
    });

    const baseUrl = this.config.get<string>('BASE_URL');
    const loginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tasket — Authorize</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #fff; border-radius: 16px; padding: 48px 40px; width: 400px; box-shadow: 0 4px 32px rgba(0,0,0,.08); text-align: center; }
    .logo { font-size: 32px; font-weight: 800; color: #6366f1; margin-bottom: 8px; }
    .subtitle { color: #64748b; font-size: 15px; margin-bottom: 32px; }
    .client-badge { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px 16px; font-size: 13px; color: #475569; margin-bottom: 28px; }
    .btn { display: flex; align-items: center; justify-content: center; gap: 12px; width: 100%; padding: 14px; border: 1.5px solid #e2e8f0; border-radius: 10px; background: #fff; font-size: 15px; font-weight: 500; color: #1e293b; cursor: pointer; text-decoration: none; transition: all .15s; }
    .btn:hover { background: #f8fafc; border-color: #cbd5e1; }
    .btn svg { width: 20px; height: 20px; flex-shrink: 0; }
    .divider { font-size: 12px; color: #94a3b8; margin: 16px 0; }
    .scope-note { font-size: 12px; color: #94a3b8; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">⚡ Tasket</div>
    <p class="subtitle">Sign in to authorize access</p>
    <div class="client-badge">Authorizing: <strong>${clientId}</strong></div>
    <a href="${baseUrl}/auth/google?state=${mcpStateId}" class="btn">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
      </svg>
      Continue with Google
    </a>
    <p class="scope-note">Grants access: ${scope}</p>
  </div>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html');
    return res.send(loginHtml);
  }

  // ── Token Exchange ─────────────────────────────────────────────────

  @Post('oauth/token')
  async token(@Body() body: any) {
    if (body.grant_type === 'refresh_token') {
      return this.oauthService.exchangeRefreshToken({ refresh_token: body.refresh_token, client_id: body.client_id });
    }
    return this.oauthService.exchangeCode({ code: body.code, client_id: body.client_id, code_verifier: body.code_verifier });
  }

  // ── Revocation ─────────────────────────────────────────────────────

  @Post('oauth/revoke')
  async revoke(@Body() body: any) {
    await this.oauthService.revokeToken(body.token, body.client_id);
    return {};
  }
}
