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

import AbilityStateData from 'application.AbilityStateData';
import { ElementName } from 'bundleManager.ElementName'
import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';
import { AbilityRunningInfo as _AbilityRunningInfo } from 'application.AbilityRunningInfo';
import { ExtensionRunningInfo as _ExtensionRunningInfo } from 'application.ExtensionRunningInfo';
import _AbilityForegroundStateObserver from 'application.AbilityForegroundStateObserver';
import _AbilityStateData from 'application.AbilityStateData';

export default namespace abilityManager {
  loadLibrary("ability_ability_manager_ani_kit.z")

  export native function nativeGetForegroundUIAbilities(): Array<AbilityStateData>;
  export native function getForegroundUIAbilitiesCallback(callback:AsyncCallbackWrapper<Array<AbilityStateData>>) : void;
  export native function nativeGetTopAbility(callback:AsyncCallbackWrapper<ElementName>) : void;
  export native function nativeGetAbilityRunningInfos(callback:AsyncCallbackWrapper<Array<AbilityRunningInfo>>) : void;

  export function getForegroundUIAbilities():Promise<Array<AbilityStateData>> {
    let p = new Promise<Array<AbilityStateData>>((resolve: (data: Array<AbilityStateData>) => void, reject: (error: Error) => void): void => {
      let executeFunc = (): Array<AbilityStateData> => {
        return nativeGetForegroundUIAbilities();
      };
      let p1 = taskpool.execute(executeFunc);
      p1.then((e :NullishType)=>{
        let abilities: Array<AbilityStateData> = e as Array<AbilityStateData>;
        resolve(abilities);
      }, (err: Error): void => {
        reject(err);
      });
    });
    return p;
  }

  export function getForegroundUIAbilities(callback: AsyncCallback<Array<AbilityStateData>, void>): void {
      let myCall = new AsyncCallbackWrapper<Array<AbilityStateData>>(callback);
      taskpool.execute((): void => {
        abilityManager.getForegroundUIAbilitiesCallback(myCall);
      })
  }

  export function getTopAbility():Promise<ElementName> {
    let p = new Promise<ElementName>((resolve: (data: ElementName)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<ElementName>((err: BusinessError<void>, data: ElementName)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeGetTopAbility(myCall);
      });
    });
    return p;
}

export function getTopAbility(callback: AsyncCallback<ElementName, void>): void {
    let myCall = new AsyncCallbackWrapper<ElementName>(callback);
    taskpool.execute( (): void => {
        abilityManager.nativeGetTopAbility(myCall);
    });
}

  function getAbilityRunningInfos(): Promise<Array<AbilityRunningInfo>> {
    return new Promise<Array<AbilityRunningInfo>>((resolve: (data: Array<AbilityRunningInfo>) => void,
      reject: (err: BusinessError<void>) => void): void => {
      let syncCall = new AsyncCallbackWrapper<Array<AbilityRunningInfo>>((err: BusinessError<void>,
        data: Array<AbilityRunningInfo>) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeGetAbilityRunningInfos(syncCall);
      });
    });
  }

  function getAbilityRunningInfos(callback: AsyncCallback<Array<AbilityRunningInfo>>): void {
    let syncCall = new AsyncCallbackWrapper<Array<AbilityRunningInfo>>(callback);
    taskpool.execute((): void => {
      abilityManager.nativeGetAbilityRunningInfos(syncCall);
    });
  }

  export enum AbilityState {
    INITIAL = 0,
    FOCUS = 2,
    FOREGROUND = 9,
    BACKGROUND = 10,
    FOREGROUNDING = 11,
    BACKGROUNDING = 12
  }

  export enum UserStatus {
    ASSERT_TERMINATE = 0,
    ASSERT_CONTINUE = 1,
    ASSERT_RETRY = 2
  }

  export type AbilityRunningInfo = _AbilityRunningInfo;

  export type AbilityStateData = _AbilityStateData;

  export type ExtensionRunningInfo = _ExtensionRunningInfo;

  export type AbilityForegroundStateObserver = _AbilityForegroundStateObserver;
}