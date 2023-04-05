import { CACHE_MANAGER, forwardRef, Inject, Injectable } from '@nestjs/common';
import { EEnviroment, ETenantStatus, UserProfile } from '@prisma/client';
import { Cache } from 'cache-manager';
import { AuthService } from 'src/auth/auth.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { TenantService } from 'src/tenant/tenant.service';
import { UpdateUserProfileDto } from 'src/user-profile/user-profile.dto';
import { _99YEAR_MILLISECONDS_ } from 'src/utils/constants';

@Injectable()
export class UserProfileService {
  constructor(
    private prismaService: PrismaService,
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
    private tenantService: TenantService,
  ) {}

  async cacheUserProfile(id: string, userProfile: UserProfile) {
    const KEY = `ha-cache:${id}`;
    const VALUE = JSON.stringify(userProfile);
    await this.cacheService.set(KEY, VALUE, _99YEAR_MILLISECONDS_);
  }

  async getCacheUserProfile(id: string) {
    const KEY = `ha-cache:${id}`;
    const value: string = await this.cacheService.get(KEY);
    let userProfile: UserProfile = null;
    if (value) {
      userProfile = JSON.parse(value);
    }
    return userProfile;
  }

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

    if (!user.profile) {
      user.profile = await this.getCacheUserProfile(user.id);
    }

    if (!user.tenants?.length) {
      const testnet = await this.tenantService.getCacheTenant(
        user.id,
        EEnviroment.TESTNET,
      );
      const mainnet = await this.tenantService.getCacheTenant(
        user.id,
        EEnviroment.MAINNET,
      );
      user.tenants = [testnet, mainnet].filter(
        (item) => !!item && item.status === ETenantStatus.ACTIVE,
      );
    }

    const lastChangedPassword = await this.authService.getLastChangedPassword(
      id,
    );

    return {
      data: {
        lastChangedPassword,
        user,
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
