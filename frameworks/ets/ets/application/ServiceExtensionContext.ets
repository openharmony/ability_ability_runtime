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
import { ConnectOptions } from 'ability.connectOptions';
import StartOptions from '@ohos.app.ability.StartOptions';
import Want from '@ohos.app.ability.Want';
import { AsyncCallback } from '@ohos.base';
import { BusinessError } from '@ohos.base';
import hilog from '@ohos.hilog';
import ExtensionContext from 'application.ExtensionContext';
import AsyncCallbackWrapper from '../utils/AbilityUtils';

export default class ServiceExtensionContext extends ExtensionContext {
  nativeServiceExtensionContext: long = 0;
  native nativeTerminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  native nativeStartAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  native nativeStartAbilitySync(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;
  native nativeStartServiceExtensionAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  native nativeStopServiceExtensionAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;

  terminateSelf(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeTerminateSelfSync(myCall);
    });
  }

  terminateSelf(): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined) => void, reject:(err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
        if (err.code == 0) {
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

  startAbility(want: Want, options: StartOptions): Promise<void> {
    let p = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
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

  startServiceExtensionAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartServiceExtensionAbilitySync(want, myCall);
    });
  }
  
  startServiceExtensionAbility(want: Want): Promise<void> {
    let p = new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStartServiceExtensionAbilitySync(want, myCall);
      });
    });
    return p;
  }

  stopServiceExtensionAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStopServiceExtensionAbility(want, myCall);
    });
  }

  stopServiceExtensionAbility(want: Want): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        this.nativeStopServiceExtensionAbility(want, myCall);
      });
    });
  }
}
