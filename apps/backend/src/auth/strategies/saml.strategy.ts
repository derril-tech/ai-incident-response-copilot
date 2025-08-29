import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-saml';
import { AuthService } from '../auth.service';

@Injectable()
export class SamlStrategy extends PassportStrategy(Strategy, 'saml') {
  constructor(private authService: AuthService) {
    super({
      entryPoint: process.env.SAML_ENTRY_POINT,
      issuer: process.env.SAML_ISSUER,
      callbackUrl: process.env.SAML_CALLBACK_URL || 'http://localhost:3001/api/v1/auth/saml/callback',
      cert: process.env.SAML_CERT,
      validateInResponseTo: false,
      disableRequestedAuthnContext: true,
    });
  }

  async validate(profile: any) {
    const user = await this.authService.validateSamlUser(profile);
    return user;
  }
}
