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
import { Configuration } from '@ohos.app.ability.Configuration';
import _AbilityForegroundStateObserver from 'application.AbilityForegroundStateObserver';
import { ExtensionRunningInfo as _ExtensionRunningInfo } from './application/ExtensionRunningInfo';


export default namespace abilityManager {
  loadLibraryWithPermissionCheck("ability_manager_ani_kit.z", "@ohos.app.ability.abilityManager")

  export native function nativeGetForegroundUIAbilities(): Array<AbilityStateData>;
  export native function getForegroundUIAbilitiesCallback(callback:AsyncCallbackWrapper<Array<AbilityStateData>>) : void;
  export native function nativeGetTopAbility(callback:AsyncCallbackWrapper<ElementName>) : void;
  export native function nativeCheckSystemApp() : void;
  export native function nativeGetTopAbilityCheck() : void;
  export native function nativeGetAbilityRunningInfos(callback:AsyncCallbackWrapper<Array<AbilityRunningInfo>>) : void;
  export native function nativeIsEmbeddedOpenAllowed(context: Context, appId: string, callback:AsyncCallbackWrapper<boolean>) : void;
  export native function nativeIsEmbeddedOpenAllowedCheck(context: Context): void;
  export native function nativeOn(type:string, observer: AbilityForegroundStateObserver): void;
  export native function nativeOff(type:string, observer?: AbilityForegroundStateObserver): void;
  export native function nativeNotifyDebugAssertResult(sessionId: string, status: UserStatus, callback: AsyncCallbackWrapper<void>): void;
  export native function nativeNotifyDebugAssertResultCheck(sessionId: string, status: UserStatus): void;
  export native function nativeSetResidentProcessEnabled(bundleName: string, enable: boolean, callback: AsyncCallbackWrapper<void>): void;
  export native function nativeSetResidentProcessEnabledCheck(bundleName: string): void;
  export native function nativeAcquireShareData(missionId: int, callback: AsyncCallbackWrapper<Record<string, Object>>): void;
  export native function nativeUpdateConfiguration(config: Configuration, callback: AsyncCallbackWrapper<void>): void;
  export native function nativeQueryAtomicServiceStartupRule(context: Context, appId: string, callback:AsyncCallbackWrapper<AtomicServiceStartupRule>) : void;
  export native function nativeQueryAtomicServiceStartupRuleCheck(context: Context): void;
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
    abilityManager.nativeGetTopAbilityCheck();
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
      abilityManager.nativeGetTopAbilityCheck();
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
    abilityManager.nativeIsEmbeddedOpenAllowedCheck(context);
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

 function notifyDebugAssertResult(sessionId: string, status: UserStatus): Promise<void> {
  abilityManager.nativeNotifyDebugAssertResultCheck(sessionId, status);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeNotifyDebugAssertResult(sessionId, status, asyncCall);
      });
    });
  }

  function setResidentProcessEnabled(bundleName: string, enable: boolean): Promise<void> {
    abilityManager.nativeSetResidentProcessEnabledCheck(bundleName);
    return new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeSetResidentProcessEnabled(bundleName, enable, asyncCall);
      });
    });
  }

  function acquireShareData(missionId: int, callback: AsyncCallback<Record<string, Object>>): void {
    let asyncCall = new AsyncCallbackWrapper<Record<string, Object>>(callback);
    taskpool.execute( (): void => {
        abilityManager.nativeAcquireShareData(missionId, asyncCall);
    });
  }

  function acquireShareData(missionId: int): Promise<Record<string, Object>> {
    return new Promise<Record<string, Object>>((resolve: (data: Record<string, Object>) => void,
      reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<Record<string, Object>>((err: BusinessError | null,
        data: Record<string, Object> | undefined) => {
        if (err == null || err.code == 0) {
          resolve(data as Record<string, Object>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeAcquireShareData(missionId, asyncCall);
      });
    });
  }

  function updateConfiguration(config: Configuration, callback: AsyncCallback<void>): void {
    let asyncCall = new AsyncCallbackWrapper<void>(callback);
    abilityManager.nativeUpdateConfiguration(config, asyncCall);
  }

  function updateConfiguration(config: Configuration): Promise<void> {
    return new Promise<void>((resolve: (data: undefined) => void,
      reject: (err: BusinessError) => void): void => {
      let asyncCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      abilityManager.nativeUpdateConfiguration(config, asyncCall);
    });
  }

  export function onAbilityForegroundState(observer: AbilityForegroundStateObserver): void {
    abilityManager.nativeOn('abilityForegroundState', observer);
  }

  export function offAbilityForegroundState(observer?: AbilityForegroundStateObserver): void {
    abilityManager.nativeOff('abilityForegroundState', observer);
  }

  function queryAtomicServiceStartupRule(context: Context, appId: string): Promise<AtomicServiceStartupRule> {
    abilityManager.nativeQueryAtomicServiceStartupRuleCheck(context);
    return new Promise<AtomicServiceStartupRule>((resolve:(data:AtomicServiceStartupRule)=>void, reject:(err: BusinessError | null)=>void):void => {
      let asyncCall = new AsyncCallbackWrapper<AtomicServiceStartupRule>((err: BusinessError | null, data: AtomicServiceStartupRule | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as AtomicServiceStartupRule);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        abilityManager.nativeQueryAtomicServiceStartupRule(context, appId, asyncCall);
      })
    });
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

  export interface AtomicServiceStartupRule {
    isOpenAllowed: boolean;
    isEmbeddedAllowed: boolean;
  }

  class AtomicServiceStartupRuleImpl implements AtomicServiceStartupRule {
    isOpenAllowed: boolean;
    isEmbeddedAllowed: boolean;
  }

  export type AbilityRunningInfo = _AbilityRunningInfo;

  export type AbilityStateData = _AbilityStateData;

  export type AbilityForegroundStateObserver = _AbilityForegroundStateObserver;

  export type ExtensionRunningInfo = _ExtensionRunningInfo;
}