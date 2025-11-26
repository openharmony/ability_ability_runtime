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

import { AbilityResult } from 'ability.abilityResult';
import { AsyncCallback } from '@ohos.base';
import { BusinessError } from '@ohos.base';
import { ConnectOptions } from 'ability.connectOptions';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import AtomicServiceOptions from '@ohos.app.ability.AtomicServiceOptions';
import ExtensionContext from 'application.ExtensionContext';
import OpenLinkOptions from '@ohos.app.ability.OpenLinkOptions';
import StartOptions from '@ohos.app.ability.StartOptions';
import Want from '@ohos.app.ability.Want';
import ConfigurationConstant from '@ohos.app.ability.ConfigurationConstant';
import UIServiceProxy from 'application.UIServiceProxy';
import UIServiceExtensionConnectCallback from 'application.UIServiceExtensionConnectCallback';

class Cleaner {
  static callback(cleaner: Cleaner): void {
      cleaner.clean()
  }
  constructor(targetPtr: long) {
      this.targetPtr = targetPtr
  }
  native clean(): void
  private targetPtr: long = 0
}
let destroyRegister = new FinalizationRegistry<Cleaner>(Cleaner.callback)
let unregisterToken = new object()

export default class UIExtensionContext extends ExtensionContext {
  static {
    loadLibrary("ui_extension_context_ani_kit.z");
  }

  nativeExtensionContext:long = 0;
  private cleaner: Cleaner | null = null;
  registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
  }
  unregisterCleaner(): void {
      destroyRegister.unregister(unregisterToken);
  }
  constructor(context:long) {
    if(this.nativeExtensionContext == 0){
          this.nativeExtensionContext = context;
    }
    this.registerCleaner(this.nativeExtensionContext)
  }
  private static native nativeTransferStatic(input: ESValue, type: string): Object;
  private static native nativeTransferDynamic(input: Object): ESValue;
  private static contextType: string = 'UIExtensionContext';

  static transferStatic(input: Any): Object {
    let type: string = '';
    try {
      type = ESValue.wrap(input).getProperty('__context_impl__').getProperty('contextType').toString();
    } catch (err) {
      console.log('transferStatic err: ' + err.toString());
    }
    console.log('transferStatic type: ' + type);
    return UIExtensionContext.nativeTransferStatic(ESValue.wrap(input), type);
  }

  static transferDynamic(input: Object): Any {
    return UIExtensionContext.nativeTransferDynamic(input).unwrap();
  }
  native terminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  native terminateSelfWithResultSync(parameter: AbilityResult, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbility(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;
  private native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): long;
  private native nativeDisconnectServiceExtensionAbilitySync(connection: long, callback: AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilityForResult(want: Want, callback:AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeStartAbilityForResult(want: Want, startOptions: StartOptions,
    callback:AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeStartServiceExtensionAbilityWithAccount(want: Want, accountId: int,
    callback: AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilityForResultAsCaller(want: Want,
    callback: AsyncCallbackWrapper<AbilityResult>, options?: StartOptions): void;
  private native nativeStartServiceExtensionAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;
  private native nativeSetHostPageOverlayForbidden(isForbidden: boolean): void;
  native setColorMode(colorMode: ConfigurationConstant.ColorMode): void;
  native nativeReportDrawnCompleted(callback:AsyncCallbackWrapper<void>): void;
  private native nativeConnectUIServiceExtensionAbility(want: Want, uiServiceExtConCallback: UIServiceExtensionConnectCallback, callback:AsyncCallbackWrapper<UIServiceProxy>): void;
  private native nativeStartUIServiceExtensionAbility(want: Want, callback:AsyncCallbackWrapper<void>): void;
  private native nativeDisconnectUIServiceExtensionAbility(proxy: UIServiceProxy, callback:AsyncCallbackWrapper<void>): void;
  private native nativeWantCheck(want: Want): void;
  private native nativeDisconnectUIServiceExtensionCheck(proxy: UIServiceProxy) : void;
  private native nativeStartUIAbilities(wantList: Array<Want>, callback: AsyncCallbackWrapper<void>): void;
  private native nativeStartUIAbilitiesInSplitWindowMode(primaryWindowId: int, secondaryWant: Want, callback:AsyncCallbackWrapper<void>) : void;
  private native nativeOpenLinkSync(link: string, syncCallback:AsyncCallbackWrapper<void>,
    options?: OpenLinkOptions, callback?: AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeOpenLinkCheck(link: string): void;
  private native nativeOpenAtomicService(appId: string, syncCallback: AsyncCallbackWrapper<AbilityResult>,
    options?: AtomicServiceOptions): void;
  private native nativeOpenAtomicServiceCheck(): void;
  terminateSelf(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.terminateSelfSync(myCall);
    });
  }

  terminateSelf(): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined) => void, reject:(err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.terminateSelfSync(myCall);
      });
    });
    return p;
  }

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.terminateSelfWithResultSync(parameter, myCall);
    });
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.terminateSelfWithResultSync(parameter, myCall);
      });
    });
    return p;
  }

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbility(want, myCall);
    });
  }

  startAbility(want: Want, options: StartOptions, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbility(want, options, myCall);
    });
  }

  startAbility(want: Want, options?: StartOptions): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        if (options == null) {
          this.nativeStartAbility(want, myCall);
        } else {
          this.nativeStartAbility(want, options as StartOptions, myCall);
        }
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
  }

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): long {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connection: long, callback: AsyncCallback<void>): void {
    let syncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeDisconnectServiceExtensionAbilitySync(connection, syncCall);
    });
  }

  disconnectServiceExtensionAbility(connection: long): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeDisconnectServiceExtensionAbilitySync(connection, syncCall);
      })
    });
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

  startAbilityForResult(want: Want, startOptions?: StartOptions): Promise<AbilityResult> {
    return new Promise<AbilityResult>((resolve: (data: AbilityResult) => void,
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
        if (startOptions == null) {
          this.nativeStartAbilityForResult(want, myCall);
        } else {
          this.nativeStartAbilityForResult(want, startOptions as StartOptions, myCall);
        }
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
  }

  reportDrawnCompleted(callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeReportDrawnCompleted(myCall);
    });
  }

  connectUIServiceExtensionAbility(want: Want, callback: UIServiceExtensionConnectCallback) : Promise<UIServiceProxy> {
    this.nativeWantCheck(want);
    return new Promise<UIServiceProxy>((resolve: (data: UIServiceProxy) => void,
      reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<UIServiceProxy>((err: BusinessError | null, data: UIServiceProxy | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as UIServiceProxy);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeConnectUIServiceExtensionAbility(want, callback, myCall);
      });
    });
  }

  startUIServiceExtensionAbility(want: Want): Promise<void> {
    this.nativeWantCheck(want);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartUIServiceExtensionAbility(want, myCall);
      });
    });
  }

  disconnectUIServiceExtensionAbility(proxy: UIServiceProxy): Promise<void> {
    this.nativeDisconnectUIServiceExtensionCheck(proxy);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeDisconnectUIServiceExtensionAbility(proxy, myCall);
      });
    });
  }

  startServiceExtensionAbilityWithAccount(want: Want, accountId: int): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartServiceExtensionAbilityWithAccount(want, accountId, myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  startAbilityForResultAsCaller(want: Want, options?: StartOptions): Promise<AbilityResult> {
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
        this.nativeStartAbilityForResultAsCaller(want, myCall, options);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
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
      taskpool.execute((): void => {
        this.nativeStartServiceExtensionAbility(want, myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  setHostPageOverlayForbidden(isForbidden: boolean) : void {
    this.nativeSetHostPageOverlayForbidden(isForbidden);
  }

  openLink(link: string, options?: OpenLinkOptions, callback?: AsyncCallback<AbilityResult, void>): Promise<void> {
    this.nativeOpenLinkCheck(link);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let finalOptions: OpenLinkOptions | undefined = undefined;
      if (options) {
        finalOptions = options;
      }
      let callParam: AsyncCallbackWrapper<AbilityResult> | undefined = undefined;
      if (callback) {
        callParam = new AsyncCallbackWrapper<AbilityResult>(callback);
      }
      let syncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute(() => {
        this.nativeOpenLinkSync(link, syncCall, finalOptions, callParam);
      });
    });
  }

  openAtomicService(appId: string, options?: AtomicServiceOptions): Promise<AbilityResult> {
    this.nativeOpenAtomicServiceCheck();
    return new Promise<AbilityResult>((resolve: (data: AbilityResult) => void, reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError | null, data: AbilityResult | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as AbilityResult);
        } else {
          reject(err);
        }
      });
      let finalOptions: AtomicServiceOptions | undefined = undefined;
      if (options) {
        finalOptions = options;
      }
      taskpool.execute(() => {
        this.nativeOpenAtomicService(appId, syncCall, finalOptions);
      });
    });
  }

  startUIAbilitiesInSplitWindowMode(primaryWindowId: int, secondaryWant: Want): Promise<void> {
    this.nativeWantCheck(secondaryWant);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartUIAbilitiesInSplitWindowMode(primaryWindowId, secondaryWant, myCall);
      });
    });
  }

  startUIAbilities(wantList: Array<Want>): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartUIAbilities(wantList, myCall);
      });
    });
  }
}