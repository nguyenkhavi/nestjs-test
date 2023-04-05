import { CACHE_MANAGER, Inject, Injectable } from '@nestjs/common';
import { Cache } from 'cache-manager';

@Injectable()
export class AppService {
  constructor(
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
  ) {}
  getHello(): string {
    return 'Hello World!';
  }

  async getCacheStore() {
    const keys = await this.cacheService.store.keys();

    //Loop through keys and get data
    const allData: { [key: string]: any } = {};
    for (const key of keys) {
      allData[key] = await this.cacheService.get(key);
    }
    return allData;
  }
}
