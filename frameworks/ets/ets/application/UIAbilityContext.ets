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
import { ConnectOptions } from 'ability.connectOptions';
import Context from 'application.Context';
import window from '@ohos.window';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import OpenLinkOptions from '@ohos.app.ability.OpenLinkOptions';
import { HapModuleInfo } from 'bundleManager.HapModuleInfo';
import ConfigurationConstant from '@ohos.app.ability.ConfigurationConstant';
import AbilityStartCallback from 'application.AbilityStartCallback';
import AtomicServiceOptions from '@ohos.app.ability.AtomicServiceOptions';

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
    loadLibrary("ability_context_ani_kit.z");
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

  private static native nativeTransferStatic(input: ESValue, type: string): Object;
  private static native nativeTransferDynamic(input: Object): ESValue;
  private static contextType: string = 'UIAbilityContext';

  static transferStatic(input: Any): Object {
    let type: string = '';
    try {
      type = ESValue.wrap(input).getProperty('__context_impl__').getProperty('contextType').toString();
    } catch (err) {
      console.log('transferStatic err: ' + err.toString());
    }
    console.log('transferStatic type: ' + type);
    return UIAbilityContext.nativeTransferStatic(ESValue.wrap(input), type);
  }
  static transferDynamic(input: Object): Any {
    return UIAbilityContext.nativeTransferDynamic(input).unwrap();
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

  private native nativeBackToCallerAbilityWithResult(abilityResult: AbilityResult, requestCode: string, callback: AsyncCallbackWrapper<void>): void;

  private native nativeSetMissionLabel(label: string, callback: AsyncCallbackWrapper<void>): void;

  private native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): long;

  private native nativeDisconnectServiceExtensionAbility(connection: long, callback: AsyncCallbackWrapper<void>): void;

  private native nativeSetColorMode(colorMode: ConfigurationConstant.ColorMode): void;

  private native nativeStartAbilityByTypeSync(type: string, wantParam: Record<string, Object>,
    startCallback: AbilityStartCallback): BusinessError;

  private native nativeOpenAtomicService(appId: string, callback: AsyncCallbackWrapper<AbilityResult>, options?: AtomicServiceOptions): void;
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

  backToCallerAbilityWithResult(abilityResult: AbilityResult, requestCode: string): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeBackToCallerAbilityWithResult(abilityResult, requestCode, syncCall);
      });
    });
  }

  setMissionLabel(label: string, callback: AsyncCallback<void>): void {
    let syncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeSetMissionLabel(label, syncCall);
    });
  }

  setMissionLabel(label: string): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeSetMissionLabel(label, syncCall);
      });
    });
  }

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): long {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connection: long, callback: AsyncCallback<void>): void {
    let syncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeDisconnectServiceExtensionAbility(connection, syncCall);
    });
  }

  disconnectServiceExtensionAbility(connection: long): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeDisconnectServiceExtensionAbility(connection, callback);
      })
    });
  }

  setColorMode(colorMode: ConfigurationConstant.ColorMode): void {
    this.nativeSetColorMode(colorMode);
  }

  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback,
    callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute((): BusinessError => {
      return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
    });
    p1.then((e: NullishType) => {
      let retError = e as BusinessError;
      if (retError.code === 0) {
        callback(null, undefined);
      } else {
        callback(retError, undefined);
      }    
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  startAbilityByType(type: string, wantParam: Record<string, Object>,
    startCallback: AbilityStartCallback): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
      let p1 = taskpool.execute((): BusinessError => {
        return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
      });
      p1.then((e: NullishType) => {
        let retError = e as BusinessError;
        if (retError.code === 0) {
          resolve(undefined);
        } else {
          reject(retError);
        }
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  openAtomicService(appId: string, options?: AtomicServiceOptions): Promise<AbilityResult> {
    return new Promise<AbilityResult>((resolve: (data: AbilityResult) => void, reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeOpenAtomicService(appId, asyncCall, options);
      });
    });
  }
}
