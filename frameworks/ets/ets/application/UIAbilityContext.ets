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

import { AbilityInfo } from 'bundleManager.AbilityInfo';
import Want from '@ohos.app.ability.Want';
import StartOptions from '@ohos.app.ability.StartOptions';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { AbilityResult } from 'ability.abilityResult';
import { Configuration } from '@ohos.app.ability.Configuration';
import Context from 'application.Context';
import window from '@ohos.window';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import OpenLinkOptions from '@ohos.app.ability.OpenLinkOptions';
import { HapModuleInfo } from 'bundleManager.HapModuleInfo';

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

export default class UIAbilityContext extends Context {
  static {
    loadLibrary("context_ani");
  }

  private cleaner: Cleaner | null = null;
  etsAbilityContextPtr: long = 0;
  config: Configuration;
  abilityInfo: AbilityInfo;
  windowStage: window.WindowStage;
  currentHapModuleInfo: HapModuleInfo;

  native constructor();

  constructor(config: Configuration, abilityInfo: AbilityInfo, windowStage: window.WindowStage, currentHapModuleInfo: HapModuleInfo) {
    super();
    this.config = config;
    this.abilityInfo = abilityInfo;
    this.windowStage = windowStage;
    this.currentHapModuleInfo = currentHapModuleInfo;
  }

  private setEtsAbilityContextPtr(ptr: long) {
    if (this.etsAbilityContextPtr == 0) {
      this.etsAbilityContextPtr = ptr;
    }
    this.registerCleaner(this.etsAbilityContextPtr);
  }

  registerCleaner(ptr: long): void {
    this.cleaner = new Cleaner(ptr);
    destroyRegister.register(this, this.cleaner!, unregisterToken);
  }

  unregisterCleaner(): void {
    destroyRegister.unregister(unregisterToken);
  }

  private native nativeStartAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;

  private native nativeStartAbilitySync(want: Want, options: StartOptions, callback: AsyncCallbackWrapper<void>): void;

  private native nativeStartAbilityForResult(want: Want, callback: AsyncCallbackWrapper<AbilityResult>): void;

  private native nativeStartAbilityForResult(want: Want, startOptions: StartOptions,
    callback: AsyncCallbackWrapper<AbilityResult>): void;

  private native nativeTerminateSelfSync(callback: AsyncCallbackWrapper<void>): void;

  private native nativeTerminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallbackWrapper<void>): void;

  private native nativeReportDrawnCompletedSync(callback: AsyncCallbackWrapper<void>): void;

  private native nativeStartServiceExtensionAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;

  private native nativeOpenLink(link: string, myCallback:AsyncCallbackWrapper<void>, options?: OpenLinkOptions, callback?: AsyncCallbackWrapper<AbilityResult>): void;

  private native nativeIsTerminating(): boolean;

  private native nativeMoveAbilityToBackground(callback: AsyncCallbackWrapper<void>): void;

  private native nativeRequestModalUIExtension(pickerWant: Want, callback: AsyncCallbackWrapper<void>): void;

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbilitySync(want, myCall);
    });
  }

  startAbility(want: Want, options: StartOptions, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbilitySync(want, options, myCall);
    });
  }

  startAbility(want: Want): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeStartAbilitySync(want, myCall);
        });
      });
    return p;
  }

  startAbility(want: Want, options: StartOptions): Promise<void> {
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
          this.nativeStartAbilitySync(want, options, myCall);
        });
      });
    return p;
  }

  startAbilityForResult(want: Want, callback: AsyncCallback<AbilityResult, void>): void {
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbilityForResult(want, myCall);
    });
  }

  startAbilityForResult(want: Want, startOptions: StartOptions, callback: AsyncCallback<AbilityResult, void>): void {
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbilityForResult(want, startOptions, myCall);
    });
  }

  startAbilityForResult(want: Want): Promise<AbilityResult> {
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult) => void,
      reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartAbilityForResult(want, myCall);
      });
    });
    return p;
  }

  startAbilityForResult(want: Want, startOptions: StartOptions): Promise<AbilityResult> {
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult) => void,
      reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartAbilityForResult(want, startOptions, myCall);
      });
    });
    return p;
  }

  terminateSelf(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeTerminateSelfSync(myCall);
    });
  }

  terminateSelf(): Promise<void> {
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
          this.nativeTerminateSelfSync(myCall);
        });
      });
    return p;
  }

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeTerminateSelfWithResult(parameter, myCall);
    });
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<void> {
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
          this.nativeTerminateSelfWithResult(parameter, myCall);
        });
      });
    return p;
  }

  reportDrawnCompleted(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeReportDrawnCompletedSync(myCall);
    });
  }

  startServiceExtensionAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    this.nativeStartServiceExtensionAbility(want, myCall);
  }

  startServiceExtensionAbility(want: Want): Promise<void> {
    return new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      this.nativeStartServiceExtensionAbility(want, myCall);
    });
  }

  openLink(link: string, options?: OpenLinkOptions, callback?: AsyncCallback<AbilityResult, void>): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      let callParam: AsyncCallbackWrapper<AbilityResult> | undefined = undefined;
      if (callback) {
        callParam = new AsyncCallbackWrapper<AbilityResult>(callback);
      }
      taskpool.execute(() => {
        this.nativeOpenLink(link, myCall, options, callParam);
      });
    });
  }

  isTerminating(): boolean {
    return this.nativeIsTerminating();
  }

  moveAbilityToBackground(): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeMoveAbilityToBackground(syncCall);
      });
    });
  }

  requestModalUIExtension(pickerWant: Want, callback: AsyncCallback<void>): void {
    let syncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeRequestModalUIExtension(pickerWant, syncCall);
    });
  }

  requestModalUIExtension(pickerWant: Want): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeRequestModalUIExtension(pickerWant, syncCall);
      });
    });
  }
}
