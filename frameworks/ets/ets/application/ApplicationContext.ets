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

import Context from 'application.Context'
import { BusinessError, AsyncCallback } from '@ohos.base'
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import Want from '@ohos.app.ability.Want';
import { ProcessInformation } from 'application.ProcessInformation';
import ConfigurationConstant from '@ohos.app.ability.ConfigurationConstant';

class Cleaner {
  public ptr: long = 0;

  constructor(ptr: long) {
    this.ptr = ptr;
  }

  native clean(): void;
}

export function callback(cleaner: Cleaner): void {
  cleaner.clean();
}

let destroyRegister = new FinalizationRegistry<Cleaner>(callback);
let unregisterToken = new object();

export default class ApplicationContext extends Context {
  etsApplicationContextPtr: long = 0;
  private cleaner: Cleaner | null = null;

  constructor(ptr: long) {
    if (this.etsApplicationContextPtr == 0) {
      this.etsApplicationContextPtr = ptr;
    }
    this.registerCleaner(this.etsApplicationContextPtr);
  }

  registerCleaner(ptr: long): void {
    this.cleaner = new Cleaner(ptr);
    destroyRegister.register(this, this.cleaner!, unregisterToken);
  }

  unregisterCleaner(): void {
    destroyRegister.unregister(unregisterToken);
  }
  public native nativekillAllProcessesSync(clearPageStack: boolean, callback: AsyncCallbackWrapper<void>): void;
  public native nativepreloadUIExtensionAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  public native setSupportedProcessCacheSync(isSupported : boolean):void;
  public native nativegetRunningProcessInformation(callback: AsyncCallbackWrapper<Array<ProcessInformation>>): void;
  public native nativeclearUpApplicationData(callback: AsyncCallbackWrapper<void>): void;
  public native nativesetLanguage(language: string): void;
  public native nativesetFontSizeScale(fontSizeScale: number): void;
  public native nativesetColorMode(colorMode: ConfigurationConstant.ColorMode): void;
  public native nativesetFont(font: string): void; 
  public native nativerestartApp(want: Want): void;

  setSupportedProcessCache(isSupported : boolean):void {
    this.setSupportedProcessCacheSync(isSupported);
  }
  preloadUIExtensionAbility(want: Want): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativepreloadUIExtensionAbilitySync(want, myCall);
        });
      });
    return p;
  }

  killAllProcesses(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativekillAllProcessesSync(false, myCall);
    });
  }

  killAllProcesses(): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativekillAllProcessesSync(false, myCall);
        });
      });
    return p;
  }

  killAllProcesses(clearPageStack: boolean): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativekillAllProcessesSync(clearPageStack, myCall);
        });
      });
    return p;
  }

  getRunningProcessInformation(callback: AsyncCallback<Array<ProcessInformation>>): void {
    let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>(callback);
    taskpool.execute((): void => {
      this.nativegetRunningProcessInformation(myCall);
    });
  }

  getRunningProcessInformation(): Promise<Array<ProcessInformation>> {
    let p = new Promise<Array<ProcessInformation>>((resolve: (data: Array<ProcessInformation>) => void,
      reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError | null,
        data: Array<ProcessInformation> | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as Array<ProcessInformation>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativegetRunningProcessInformation(myCall);
      });
    });
    return p;
  }

  clearUpApplicationData(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeclearUpApplicationData(myCall);
    });
  }

  clearUpApplicationData(): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeclearUpApplicationData(myCall);
        });
      });
    return p;
  }

  setLanguage(language: string): void {
    this.nativesetLanguage(language);
  }

  setFontSizeScale(fontSizeScale: number): void {
    this.nativesetFontSizeScale(fontSizeScale);
  }

  setColorMode(colorMode: ConfigurationConstant.ColorMode): void {
    this.nativesetColorMode(colorMode);
  }

  setFont(font: string): void {
    this.nativesetFont(font);
  }

  restartApp(want: Want): void {
    this.nativerestartApp(want);
  }
}