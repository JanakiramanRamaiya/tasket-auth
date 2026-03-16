import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(config: ConfigService) {
    super({
      clientID: config.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: config.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: `${config.get<string>('BASE_URL')}/auth/google/callback`,
      scope: ['email', 'profile'],
      passReqToCallback: true,
    });
  }

  async validate(req: any, _at: string, _rt: string, profile: any, done: VerifyCallback) {
    done(null, {
      googleId: profile.id,
      email: profile.emails?.[0]?.value,
      displayName: profile.displayName,
      avatarUrl: profile.photos?.[0]?.value ?? null,
      // carry MCP PKCE state through the social login redirect
      mcpStateId: req.query?.state ?? null,
    });
  }
}
