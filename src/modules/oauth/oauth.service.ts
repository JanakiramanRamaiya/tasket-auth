import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../database/prisma.service';
import { SignJWT, importPKCS8, importSPKI, exportJWK, calculateJwkThumbprint } from 'jose';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';

export interface McpAuthState {
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  redirectUri: string;
  clientState: string;
  scopes: string[];
  expiresAt: number;
}

// In-memory store for MCP PKCE state during social login (5 min TTL)
const mcpStateStore = new Map<string, McpAuthState>();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of mcpStateStore) if (v.expiresAt < now) mcpStateStore.delete(k);
}, 5 * 60 * 1000);

@Injectable()
export class OAuthService {
  constructor(private prisma: PrismaService, private config: ConfigService) {}

  // ── JWT ────────────────────────────────────────────────────────────

  async generateAccessToken(user: { id: string; email: string }, scopes = ['read', 'write']): Promise<string> {
    const pem = Buffer.from(this.config.get<string>('JWT_PRIVATE_KEY'), 'base64').toString('utf-8');
    const key = await importPKCS8(pem, 'RS256');
    return new SignJWT({ sub: user.id, email: user.email, scopes })
      .setProtectedHeader({ alg: 'RS256', kid: 'tasket-key-1' })
      .setIssuedAt()
      .setIssuer(this.config.get<string>('BASE_URL'))
      .setExpirationTime(this.config.get<string>('JWT_ACCESS_EXPIRY', '1h'))
      .sign(key);
  }

  async generateRefreshToken(clientId: string, userId: string, scopes: string[]): Promise<string> {
    const token = randomBytes(32).toString('hex');
    const expiresAt = Math.floor(Date.now() / 1000) + this.config.get<number>('JWT_REFRESH_EXPIRY_DAYS', 30) * 86400;
    await this.prisma.oAuthToken.create({ data: { token, tokenType: 'refresh', clientId, userId, scopes, expiresAt } });
    return token;
  }

  // ── JWKS ───────────────────────────────────────────────────────────

  async getJwks() {
    const pem = Buffer.from(this.config.get<string>('JWT_PUBLIC_KEY'), 'base64').toString('utf-8');
    const key = await importSPKI(pem, 'RS256');
    const jwk = await exportJWK(key);
    const thumbprint = await calculateJwkThumbprint(jwk);
    return { keys: [{ ...jwk, alg: 'RS256', use: 'sig', kid: 'tasket-key-1', x5t: thumbprint }] };
  }

  // ── Discovery ──────────────────────────────────────────────────────

  getAuthServerMetadata() {
    const base = this.config.get<string>('BASE_URL');
    return {
      issuer: base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      revocation_endpoint: `${base}/oauth/revoke`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      scopes_supported: ['read', 'write'],
    };
  }

  getProtectedResourceMetadata() {
    const base = this.config.get<string>('BASE_URL');
    return {
      resource: `${this.config.get<string>('BASE_URL')}/mcp`,
      authorization_servers: [base],
      scopes_supported: ['read', 'write'],
      bearer_methods_supported: ['header'],
    };
  }

  // ── Dynamic Client Registration ────────────────────────────────────

  async registerClient(dto: { client_name?: string; redirect_uris: string[]; grant_types?: string[]; response_types?: string[] }) {
    const clientId = `tasket-${uuidv4().slice(0, 8)}`;
    const clientSecret = randomBytes(32).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    await this.prisma.oAuthClient.create({
      data: {
        clientId, clientSecret,
        redirectUris: dto.redirect_uris,
        grantTypes: dto.grant_types ?? ['authorization_code'],
        responseTypes: dto.response_types ?? ['code'],
        clientName: dto.client_name ?? null,
        clientUri: null,
        clientIdIssuedAt: now,
      },
    });
    return { client_id: clientId, client_secret: clientSecret, client_id_issued_at: now, redirect_uris: dto.redirect_uris };
  }

  // ── MCP PKCE State ─────────────────────────────────────────────────

  storeMcpAuthState(params: Omit<McpAuthState, 'expiresAt'>): string {
    const id = uuidv4();
    mcpStateStore.set(id, { ...params, expiresAt: Date.now() + 5 * 60 * 1000 });
    return id;
  }

  getMcpAuthState(id: string): McpAuthState | null {
    const s = mcpStateStore.get(id);
    if (!s || s.expiresAt < Date.now()) { mcpStateStore.delete(id); return null; }
    return s;
  }

  clearMcpAuthState(id: string) { mcpStateStore.delete(id); }

  // ── Authorization code issuance ────────────────────────────────────

  async issueMcpAuthCode(userId: string, state: McpAuthState): Promise<string> {
    const code = randomBytes(32).toString('hex');
    await this.prisma.oAuthCode.create({
      data: {
        code, clientId: state.clientId, userId,
        redirectUri: state.redirectUri,
        codeChallenge: state.codeChallenge,
        codeChallengeMethod: state.codeChallengeMethod ?? 'S256',
        scopes: state.scopes,
        expiresAt: Math.floor(Date.now() / 1000) + 300,
      },
    });
    return code;
  }

  // ── Token Exchange ─────────────────────────────────────────────────

  async exchangeCode(dto: { code: string; client_id: string; code_verifier: string }) {
    const now = Math.floor(Date.now() / 1000);
    const row = await this.prisma.oAuthCode.findFirst({
      where: { code: dto.code, clientId: dto.client_id, used: false, expiresAt: { gt: now } },
      include: { user: true },
    });
    if (!row) throw new UnauthorizedException('Invalid or expired authorization code');

    const computed = createHash('sha256').update(dto.code_verifier).digest('base64url');
    if (computed !== row.codeChallenge) throw new UnauthorizedException('PKCE verification failed');

    await this.prisma.oAuthCode.update({ where: { code: dto.code }, data: { used: true } });

    const accessToken = await this.generateAccessToken(row.user, row.scopes);
    const refreshToken = await this.generateRefreshToken(dto.client_id, row.userId, row.scopes);
    return { access_token: accessToken, token_type: 'bearer', expires_in: 3600, refresh_token: refreshToken, scope: row.scopes.join(' ') };
  }

  async exchangeRefreshToken(dto: { refresh_token: string; client_id: string }) {
    const now = Math.floor(Date.now() / 1000);
    const row = await this.prisma.oAuthToken.findFirst({
      where: { token: dto.refresh_token, tokenType: 'refresh', clientId: dto.client_id, expiresAt: { gt: now } },
      include: { user: true },
    });
    if (!row) throw new UnauthorizedException('Invalid or expired refresh token');

    await this.prisma.oAuthToken.delete({ where: { token: dto.refresh_token } });
    const accessToken = await this.generateAccessToken(row.user, row.scopes);
    const newRefresh = await this.generateRefreshToken(dto.client_id, row.userId, row.scopes);
    return { access_token: accessToken, token_type: 'bearer', expires_in: 3600, refresh_token: newRefresh, scope: row.scopes.join(' ') };
  }

  async revokeToken(token: string, clientId: string) {
    await this.prisma.oAuthToken.deleteMany({ where: { token, clientId } });
  }
}
