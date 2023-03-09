import { forwardRef, Inject, Injectable } from '@nestjs/common';
import { UserProfile } from '@prisma/client';
import { AuthService } from 'src/auth/auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { UpdateUserProfileDto } from 'src/user-profile/user-profile.dto';

@Injectable()
export class UserProfileService {
  constructor(
    private prismaService: PrismaService,
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
  ) {}
  async createDefaultProfile(uid: string, name?: string, avatar?: string) {
    const userProfile = await this.prismaService.userProfile.create({
      data: {
        userId: uid,
        name,
        avatar,
      },
    });
    return userProfile;
  }

  async getMyProfile(id: string) {
    const user = await this.authService.getUserWithoutSensitive(id);
    const profile = await this.prismaService.userProfile.findUniqueOrThrow({
      where: {
        userId: id,
      },
    });

    return {
      data: {
        user,
        profile,
      },
    };
  }

  async updateMyProfile(id: string, body: UpdateUserProfileDto) {
    const { name, avatar } = body;
    const data: Partial<UserProfile> = {};
    if (name) {
      data['name'] = name;
    }
    if (avatar) {
      data['avatar'] = avatar;
    }
    const updated = await this.prismaService.userProfile.update({
      where: {
        userId: id,
      },
      data,
    });
    return { data: updated };
  }
  // create(createUserProfileDto: CreateUserProfileDto) {
  //   return 'This action adds a new userProfile';
  // }

  // findAll() {
  //   return `This action returns all userProfile`;
  // }

  // findOne(id: number) {
  //   return `This action returns a #${id} userProfile`;
  // }

  // update(id: number, updateUserProfileDto: UpdateUserProfileDto) {
  //   return `This action updates a #${id} userProfile`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} userProfile`;
  // }
}
