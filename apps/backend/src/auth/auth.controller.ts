import { Controller, Post, UseGuards, Request, Body, Get } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      throw new Error('Invalid credentials');
    }
    return this.authService.login(user);
  }

  @ApiOperation({ summary: 'SAML SSO login' })
  @UseGuards(AuthGuard('saml'))
  @Post('saml/login')
  async samlLogin(@Request() req) {
    return this.authService.login(req.user);
  }

  @ApiOperation({ summary: 'SAML SSO callback' })
  @UseGuards(AuthGuard('saml'))
  @Post('saml/callback')
  async samlCallback(@Request() req) {
    return this.authService.login(req.user);
  }

  @ApiOperation({ summary: 'Get current user profile' })
  @ApiBearerAuth()
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }
}
