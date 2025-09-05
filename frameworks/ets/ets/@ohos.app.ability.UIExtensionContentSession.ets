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
import { BusinessError, RecordData } from '@ohos.base';
import uiExtensionHost from '@ohos.uiExtensionHost';
import { LocalStorage } from '@ohos.arkui.stateManagement';
import AsyncCallbackWrapper from './utils/AbilityUtils';
import AbilityStartCallback from 'application.AbilityStartCallback';
import uiExtension from '@ohos.arkui.uiExtension';

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

export default class UIExtensionContentSession {
  nativeContextSession:long = 0;
  private cleaner: Cleaner | null = null;
  registerCleaner(ptr: long): void {
      this.cleaner = new Cleaner(ptr)
      destroyRegister.register(this, this.cleaner!, unregisterToken);
  }
  unregisterCleaner(): void {
      destroyRegister.unregister(unregisterToken);
  }
  constructor(contextSession:long) {
    if(this.nativeContextSession == 0){
          this.nativeContextSession = contextSession;
    }
    this.registerCleaner(this.nativeContextSession)
  }
  native nativeSendData(data: Record<string, RecordData>): void;
  native loadContent(path: string, storage?: LocalStorage): void;
  native loadContentByName(path: string, storage?: LocalStorage): void;
  native setWindowBackgroundColor(color: string): void;
  native getUIExtensionHostWindowProxy(): uiExtensionHost.UIExtensionHostWindowProxy;
  native getUIExtensionWindowProxy(): uiExtension.WindowProxy;
  native nativeSetReceiveDataCallback(callback: (data: Record<string, Object>) => void): void;
  native nativeSetReceiveDataForResultCallback(callback: (data: Record<string, Object>) => Record<string, Object>): void;
  native terminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  native terminateSelfWithResultSync(parameter: AbilityResult, callback:AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilityByTypeSync(type: string, wantParam: Record<string, RecordData>, startCallback: AbilityStartCallback): BusinessError<void>;
  native nativeSetWindowPrivacyMode(isPrivacyMode: boolean, callback:AsyncCallbackWrapper<void>): void;

  sendData(data: Record<string, RecordData>): void {
    this.nativeSendData(data);
  }

  setReceiveDataCallback(callback: (data: Record<string, Object>) => void): void {
    this.nativeSetReceiveDataCallback(callback);
  }

  setReceiveDataForResultCallback(callback: (data: Record<string, Object>) => Record<string, Object>): void {
    this.nativeSetReceiveDataForResultCallback(callback);
  }

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
    let p = new Promise<void>((resolve: (data: undefined) => void, reject:(err: BusinessError) => void): void => {
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

  startAbilityByType(type: string, wantParam: Record<string, RecordData>, startCallback: AbilityStartCallback,
    callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute((): BusinessError<void> => {
      return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
    });
    p1.then((e: NullishType) => {
      let retError = e as BusinessError<void>;
      if (retError.code === 0) {
        callback(null, undefined);
      } else {
        callback(retError, undefined);
      }      
    }, (err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  startAbilityByType(type: string, wantParam: Record<string, RecordData>,
    startCallback: AbilityStartCallback): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError<void>) => void): void => {
      let p1 = taskpool.execute((): BusinessError<void> => {
        return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
      });
      p1.then((e: NullishType) => {
        let retError = e as BusinessError<void>;
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

  setWindowPrivacyMode(isPrivacyMode: boolean): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject:(err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeSetWindowPrivacyMode(isPrivacyMode, asyncCall);
      });
    });
  }

  setWindowPrivacyMode(isPrivacyMode: boolean, callback: AsyncCallback<void>): void {
    let asyncCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeSetWindowPrivacyMode(isPrivacyMode, asyncCall);
    });
  }
}
