/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Context from 'application.Context';
import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace application {
  loadLibrary("application_ani.z")
  export native function nativeCreateModuleContext(context: Context, bundleName: string, moduleName: string,
    callback: AsyncCallbackWrapper<Context>): void;

  export native function nativeCreateBundleContext(context: Context, bundleName: string,
    callback: AsyncCallbackWrapper<Context>): void;

  export function createModuleContext(context: Context, moduleName: string): Promise<Context> {
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError<void>, data: Context) => {
          if (err.code == 0) {
            resolve(data);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          application.nativeCreateModuleContext(context, "", moduleName, myCall);
        });
      });
    return p;
  }

  export function createModuleContext(context: Context, bundleName: string, moduleName: string): Promise<Context> {
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError<void>, data: Context) => {
          if (err.code == 0) {
            resolve(data);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          application.nativeCreateModuleContext(context, bundleName, moduleName, myCall);
        });
      });
    return p;
  }

  export function createBundleContext(context: Context, bundleName: string): Promise<Context> {
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError<void>, data: Context) => {
          if (err.code == 0) {
            resolve(data);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          application.nativeCreateBundleContext(context, bundleName, myCall);
        });
      });
    return p;
  }
}