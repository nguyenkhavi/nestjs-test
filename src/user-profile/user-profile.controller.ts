import {
  Body,
  Controller,
  Get,
  Patch,
  UseGuards,
  // Post,
  // Body,
  // Patch,
  // Param,
  // Delete,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import { UpdateUserProfileDto } from 'src/user-profile/user-profile.dto';
import { Uid } from 'src/utils/decorators';
import { UserProfileService } from './user-profile.service';

@Controller('user-profile')
@ApiTags('User profile')
export class UserProfileController {
  constructor(private readonly userProfileService: UserProfileService) {}

  @Get('/me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get current user profile based-on bearer token provided',
  })
  getMyProfile(@Uid() uid: string) {
    return this.userProfileService.getMyProfile(uid);
  }

  @Patch('/me')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update current user profile based-on bearer token provided',
  })
  updateMyProfile(@Uid() uid: string, @Body() body: UpdateUserProfileDto) {
    return this.userProfileService.updateMyProfile(uid, body);
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.userProfileService.findOne(+id);
  // }

  // @Patch(':id')
  // update(
  //   @Param('id') id: string,
  //   @Body() updateUserProfileDto: UpdateUserProfileDto,
  // ) {
  //   return this.userProfileService.update(+id, updateUserProfileDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.userProfileService.remove(+id);
  // }
}
