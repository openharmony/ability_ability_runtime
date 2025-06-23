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
import AbilityStartCallback from 'application.AbilityStartCallback';
import { Configuration } from '@ohos.app.ability.Configuration';
import { ConnectOptions } from 'ability.connectOptions';
import Context from 'application.Context';
import window from '@ohos.window';
import { Caller } from '@ohos.app.ability.UIAbility';
import { HapModuleInfo } from 'bundleManager.HapModuleInfo';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import OpenLinkOptions from '@ohos.app.ability.OpenLinkOptions';
import { LocalStorage } from '@ohos.arkui.stateManagement';
import ConfigurationConstant from '@ohos.app.ability.ConfigurationConstant';

export default class UIAbilityContext extends Context {
  static {
    loadLibrary("context_ani");
  }

  config: Configuration;
  abilityInfo: AbilityInfo;
  windowStage: window.WindowStage;
  currentHapModuleInfo: HapModuleInfo;

  native constructor();

  constructor(config: Configuration, abilityInfo: AbilityInfo, windowStage: window.WindowStage,
    currentHapModuleInfo: HapModuleInfo) {
    super();
    this.config = config;
    this.abilityInfo = abilityInfo;
    this.windowStage = windowStage;
    this.currentHapModuleInfo = currentHapModuleInfo;
  }

  private static native nativeTransferStatic(input: ESValue): Object;
  private static native nativeTransferDynamic(input: Object): ESValue;
  static transferStatic(input: Any): Object {
    return UIAbilityContext.nativeTransferStatic(ESValue.wrap(input));
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

  private native nativeStartAbilityByTypeSync(type: string, wantParam: Record<string, Object>,
    startCallback: AbilityStartCallback): BusinessError;

  private native nativeStartServiceExtensionAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;

  private native nativeStartAbilityByCallSync(want: Want): Caller;

  private native nativeOpenLinkSync(link: string, myCallback: AsyncCallbackWrapper<void>, options?: OpenLinkOptions,
    callback?: AsyncCallbackWrapper<AbilityResult>): void;

  private native nativeRestoreWindowStage(localStorage: LocalStorage): boolean;

  private native nativeIsTerminating(): boolean;

  private native nativeMoveAbilityToBackground(callback: AsyncCallbackWrapper<void>): void;

  private native nativeRequestModalUIExtension(pickerWant: Want, callback: AsyncCallbackWrapper<void>): void;
  private native nativeSetColorMode(colorMode: ConfigurationConstant.ColorMode): void;

  private native nativeBackToCallerAbilityWithResult(abilityResult: AbilityResult, requestCode: string, callback: AsyncCallbackWrapper<void>): void;

  private native nativeSetMissionLabel(label: string, callback: AsyncCallbackWrapper<void>): void;

  private native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): double;

  private native nativeDisconnectServiceExtensionAbility(connection: double, callback: AsyncCallbackWrapper<void>): void;

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
    let p = new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
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
      let myCall =
        new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
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
      let myCall =
        new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
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
    let p = new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
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
    let p = new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
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

  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback,
    callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute((): BusinessError => {
      return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
    });
    p1.then((e: NullishType) => {
      let retError = e as BusinessError;
      callback(retError, undefined);
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

  startServiceExtensionAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    this.nativeStartServiceExtensionAbilitySync(want, myCall);
  }

  startServiceExtensionAbility(want: Want): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      this.nativeStartServiceExtensionAbilitySync(want, myCall);
    });
    return p;
  }

  startAbilityByCall(want: Want): Promise<Caller> {
    return taskpool.execute((): Caller => {
      return this.nativeStartAbilityByCallSync(want);
    }) as Promise<Caller>;
  }

  openLink(link: string, options?: OpenLinkOptions, callback?: AsyncCallback<AbilityResult, void>): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let finalOptions: OpenLinkOptions | undefined = undefined;
      if (options) {
        finalOptions = options;
      }
      let callParam: AsyncCallbackWrapper<AbilityResult> | undefined = undefined;
      if (callback) {
        callParam = new AsyncCallbackWrapper<AbilityResult>(callback);
      }
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeOpenLinkSync(link, myCall, finalOptions, callParam);
      });
    });
  }

  restoreWindowStage(localStorage: LocalStorage): void {
    this.nativeRestoreWindowStage(localStorage);
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

  setColorMode(colorMode: ConfigurationConstant.ColorMode): void {
    this.nativeSetColorMode(colorMode);
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

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): number {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connection: number, callback: AsyncCallback<void>): void {
    let syncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeDisconnectServiceExtensionAbility(connection, syncCall);
    });
  }

  disconnectServiceExtensionAbility(connection: number): Promise<void> {
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
}
