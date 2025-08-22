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
import AsyncCallbackWrapper from '../utils/AbilityUtils';
import ExtensionContext from 'application.ExtensionContext';
import StartOptions from '@ohos.app.ability.StartOptions';
import Want from '@ohos.app.ability.Want';

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
  native terminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  native terminateSelfWithResultSync(parameter: AbilityResult, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbility(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;

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

  startAbility(want: Want, options: StartOptions): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartAbility(want, options, myCall);
      });
    });
  }
}