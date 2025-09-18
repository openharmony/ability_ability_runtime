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
import { ExtensionRunningInfo } from 'application.ExtensionRunningInfo';
import _AbilityStateData from 'application.AbilityStateData';
import Context from 'application.Context';
import _AbilityForegroundStateObserver from 'application.AbilityForegroundStateObserver';

export default namespace abilityManager {
  loadLibraryWithPermissionCheck("ability_manager_ani_kit.z", "@ohos.app.ability.abilityManager")

  export native function nativeGetForegroundUIAbilities(): Array<AbilityStateData>;
  export native function getForegroundUIAbilitiesCallback(callback:AsyncCallbackWrapper<Array<AbilityStateData>>) : void;
  export native function nativeGetTopAbility(callback:AsyncCallbackWrapper<ElementName>) : void;
  export native function nativeCheckSystemApp() : void;
  export native function nativeGetAbilityRunningInfos(callback:AsyncCallbackWrapper<Array<AbilityRunningInfo>>) : void;
  export native function nativeIsEmbeddedOpenAllowed(context: Context, appId: string, callback:AsyncCallbackWrapper<boolean>) : void;
  export native function nativeOn(type:string, observer: AbilityForegroundStateObserver): void;
  export native function nativeOff(type:string, observer?: AbilityForegroundStateObserver): void;
  export native function nativeGetExtensionRunningInfos(upperLimit:int, callback:AsyncCallbackWrapper<Array<ExtensionRunningInfo>>) : void;

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

  export function getForegroundUIAbilities(callback: AsyncCallback<Array<AbilityStateData>>): void {
      let myCall = new AsyncCallbackWrapper<Array<AbilityStateData>>(callback);
      taskpool.execute((): void => {
        abilityManager.getForegroundUIAbilitiesCallback(myCall);
      })
  }

  export function getTopAbility():Promise<ElementName> {
    abilityManager.nativeCheckSystemApp();
    let p = new Promise<ElementName>((resolve: (data: ElementName)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<ElementName>((err: BusinessError | null, data: ElementName | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as ElementName);
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
    abilityManager.nativeCheckSystemApp();
    let myCall = new AsyncCallbackWrapper<ElementName>(callback);
    taskpool.execute( (): void => {
      abilityManager.nativeGetTopAbility(myCall);
    });
  }

  function getAbilityRunningInfos(): Promise<Array<AbilityRunningInfo>> {
    return new Promise<Array<AbilityRunningInfo>>((resolve: (data: Array<AbilityRunningInfo>) => void,
      reject: (err: BusinessError) => void): void => {
      let syncCall = new AsyncCallbackWrapper<Array<AbilityRunningInfo>>((err: BusinessError | null,
        data: Array<AbilityRunningInfo> | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as Array<AbilityRunningInfo>);
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

  function isEmbeddedOpenAllowed(context: Context, appId: string): Promise<boolean> {
    return new Promise<boolean>((resolve:(data:boolean)=>void, reject:(err: BusinessError | null)=>void):void => {
      let asyncCall = new AsyncCallbackWrapper<boolean>((err: BusinessError | null, data: boolean | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as boolean);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeIsEmbeddedOpenAllowed(context, appId, asyncCall);
      });
    });
  }

  export function on(type: 'abilityForegroundState', observer: AbilityForegroundStateObserver): void {
    abilityManager.nativeOn('abilityForegroundState', observer);
  }

  export function off(type: 'abilityForegroundState', observer?: AbilityForegroundStateObserver): void {
    abilityManager.nativeOff('abilityForegroundState', observer);
  }

  export function getExtensionRunningInfos(upperLimit: int): Promise<Array<ExtensionRunningInfo>> {
    let p = new Promise<Array<ExtensionRunningInfo>>((resolve: (data: Array<ExtensionRunningInfo>)=>void,
      reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ExtensionRunningInfo>>((err: BusinessError | null,
        data: Array<ExtensionRunningInfo> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<ExtensionRunningInfo>);
        } else {
          reject(err);
        }
      });
      taskpool.execute(():void => {
        abilityManager.nativeGetExtensionRunningInfos(upperLimit, myCall);
      });
    });
    return p;
  }

  export function getExtensionRunningInfos(upperLimit: int, callback: AsyncCallback<Array<ExtensionRunningInfo>>): void {
    let myCall = new AsyncCallbackWrapper<Array<ExtensionRunningInfo>>(callback);
    taskpool.execute( (): void => {
        abilityManager.nativeGetExtensionRunningInfos(upperLimit, myCall);
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

  export type AbilityForegroundStateObserver = _AbilityForegroundStateObserver;
}