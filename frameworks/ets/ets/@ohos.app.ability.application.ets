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
import ApplicationContext from 'application.ApplicationContext';

export default namespace application {
  loadLibrary("application_ani.z")
  export native function nativeCreateModuleContext(context: Context, bundleName: string, moduleName: string,
    callback: AsyncCallbackWrapper<Context>): void;

  export native function nativeCreateBundleContext(context: Context, bundleName: string,
    callback: AsyncCallbackWrapper<Context>): void;

  export native function nativeCreatePluginModuleContext(context: Context, pluginBundleName: string,
    pluginModuleName: string, callback: AsyncCallbackWrapper<Context>): void;

  export native function nativeGetApplicationContext(): ApplicationContext;

  export native function nativeCreateModuleContextCheck(context: Context, moduleName: string, bundleName?: string): void;
  export function createModuleContext(context: Context, moduleName: string): Promise<Context> {
    application.nativeCreateModuleContextCheck(context, moduleName);
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError | null, data: Context | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Context);
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
    application.nativeCreateModuleContextCheck(context, moduleName, bundleName);
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError | null, data: Context | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Context);
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

  export native function nativeCreateBundleContextCheck(context: Context, bundleName: string): void;
  export function createBundleContext(context: Context, bundleName: string): Promise<Context> {
    application.nativeCreateBundleContextCheck(context, bundleName);
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError | null, data: Context | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Context);
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

  export native function nativeCreatePluginModuleContextCheck(context: Context, pluginBundleName: string,
    pluginModuleName: string): void;
  export function createPluginModuleContext(context: Context, pluginBundleName: string,
    pluginModuleName: string): Promise<Context> {
    application.nativeCreatePluginModuleContextCheck(context, pluginBundleName, pluginModuleName);
    let p =
      new Promise<Context>((resolve: (data: Context) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<Context>((err: BusinessError | null, data: Context | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as Context);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          application.nativeCreatePluginModuleContext(context, pluginBundleName, pluginModuleName, myCall);
        });
      });
    return p;
  }

  export function getApplicationContext(): ApplicationContext {
    return nativeGetApplicationContext();
  }
}