/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import ExtensionContext from  'application.ExtensionContext';
import type Want from '@ohos.app.ability.Want';
import type StartOptions from '@ohos.app.ability.StartOptions';
import type AbilityStartCallback from 'application.AbilityStartCallback';
import { ConnectOptions } from 'ability.connectOptions';
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import { AsyncCallback, BusinessError, RecordData } from '@ohos.base';

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

export default class UIServiceExtensionContext extends ExtensionContext
{
  static {
    loadLibrary("ui_service_extension_context_ani_kit.z");
  }
  nativeUiExtensionContext:long = 0;
  private cleaner: Cleaner | null = null;
  registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
  }
  unregisterCleaner(): void {
      destroyRegister.unregister(unregisterToken);
  }
  constructor(context:long) {
    if(this.nativeUiExtensionContext == 0){
          this.nativeUiExtensionContext = context;
    }
    this.registerCleaner(this.nativeUiExtensionContext)
  }
  private static native nativeTransferStatic(input: ESValue, type: string): Object;

  private static native nativeTransferDynamic(input: Object): ESValue;

  private static contextType: string = 'UIServiceExtensionContext';

  static transferStatic(input: Any): Object {
    let type: string = '';
    try {
      type = ESValue.wrap(input).getProperty('__context_impl__').getProperty('contextType').toString();
    } catch (err) {
      console.log('transferStatic err: ' + err.toString());
    }
    console.log('transferStatic type: ' + type);
    return UIServiceExtensionContext.nativeTransferStatic(ESValue.wrap(input), type);
  }

  static transferDynamic(input: Object): Any {
    return UIServiceExtensionContext.nativeTransferDynamic(input).unwrap();
  }
  native nativeStartAbility(callback: AsyncCallbackWrapper<void>, want: Want, options?: StartOptions): void;
  native nativeTerminateSelf(callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbilityByType(type: string, wantParam: Record<string, RecordData>,
    abilityStartCallback: AbilityStartCallback, callback: AsyncCallbackWrapper<void>): void;
  native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): long;
  native nativeDisconnectServiceExtensionAbility(connectionId: long, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbilityCheck(want: Want, options?: StartOptions): void;
  native nativeStartAbilityByTypeCheck(type: string, wantParam: Record<string, RecordData>): void;

  startAbility(want: Want, options?: StartOptions): Promise<void> {
    this.nativeStartAbilityCheck(want, options);
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
          this.nativeStartAbility(myCall, want, options);
        });
      });
    return p;
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
        this.nativeTerminateSelf(myCall);
      });
    });
    return p;
  }

  startAbilityByType(type: string, wantParam: Record<string, RecordData>, abilityStartCallback: AbilityStartCallback): Promise<void>
  {
    this.nativeStartAbilityByTypeCheck(type, wantParam);
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
          this.nativeStartAbilityByType(type, wantParam, abilityStartCallback, myCall);
        });
      });
    return p;
  }

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): long {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connectionId: long): Promise<void> {
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
          this.nativeDisconnectServiceExtensionAbility(connectionId, myCall);
        });
      });
    return p;
  }
}