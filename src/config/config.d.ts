import {
  ConfigObject,
  ConfigFactory,
  ConfigFactoryKeyHost,
} from '@nestjs/config';

export declare module '@nestjs/config' {
  function registerAs<
    TConfig extends ConfigObject,
    TFactory extends ConfigFactory = ConfigFactory<TConfig>,
    Name extends string = '',
  >(
    token: Name,
    configFactory: TFactory,
  ): TFactory & ConfigFactoryKeyHost<ReturnType<TFactory>> & { name: Name };
}

type GetParams<T> = T extends (() => infer R extends Record<string, unknown>) &
  infer K
  ? R
  : unknown;
type DotType<
  T extends { name: string },
  Q extends string = T['name'],
> = T extends object
  ? {
      [K in keyof GetParams<T> as K extends `${infer I}` ? `${Q}.${I}` : K]:
        | number
        | string;
    }
  : '';

export type GetConfig<T, Result = 'init'> = T extends [
  infer Type extends { name: string },
  ...infer Rest,
]
  ? GetConfig<
      Rest,
      Result extends 'init' ? DotType<Type> : Result & DotType<Type>
    >
  : Result;
