import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../database/prisma.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async findOrCreateFromGoogle(profile: {
    googleId: string;
    email: string;
    displayName: string;
    avatarUrl?: string;
  }) {
    let user = await this.prisma.user.findUnique({ where: { googleId: profile.googleId } });
    if (user) return user;

    user = await this.prisma.user.findUnique({ where: { email: profile.email } });
    if (user) {
      return this.prisma.user.update({
        where: { id: user.id },
        data: { googleId: profile.googleId, avatarUrl: profile.avatarUrl ?? user.avatarUrl },
      });
    }

    return this.prisma.user.create({
      data: {
        googleId: profile.googleId,
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl,
        initials: this.makeInitials(profile.displayName),
        color: this.randomColor(),
      },
    });
  }

  private makeInitials(name: string): string {
    return name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);
  }

  private randomColor(): string {
    const colors = ['#6366f1', '#ec4899', '#f59e0b', '#10b981', '#8b5cf6', '#ef4444', '#3b82f6'];
    return colors[Math.floor(Math.random() * colors.length)];
  }
}
