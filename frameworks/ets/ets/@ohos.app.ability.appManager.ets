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
import { ProcessInformation as _ProcessInformation } from 'application.ProcessInformation';
import { RunningMultiAppInfo as _RunningMultiAppInfo } from 'application.RunningMultiAppInfo';
import _AbilityStateData from 'application.AbilityStateData';
import _AppStateData from 'application.AppStateData';
import hilog from '@ohos.hilog';
import { BusinessError, AsyncCallback } from '@ohos.base';
import _ProcessData from 'application.ProcessData';
import _ApplicationStateObserver from 'application.ApplicationStateObserver';
import AsyncCallbackWrapper from './utils/AbilityUtils';
import bundleManager from '@ohos.bundle.bundleManager';

export default namespace appManager {
loadLibrary("ability_app_manager_ani_kit.z")

export type ProcessInformation = _ProcessInformation;
export type AbilityStateData = _AbilityStateData;
export type AppStateData = _AppStateData;
export type RunningMultiAppInfo = _RunningMultiAppInfo;
export type ProcessData = _ProcessData;
export type ApplicationStateObserver = _ApplicationStateObserver;

export enum PreloadMode {
  PRESS_DOWN
}

export enum ApplicationState {
  STATE_CREATE,
  STATE_FOREGROUND,
  STATE_ACTIVE,
  STATE_BACKGROUND,
  STATE_DESTROY
}

export enum ProcessState {
    STATE_CREATE,
    STATE_FOREGROUND,
    STATE_ACTIVE,
    STATE_BACKGROUND,
    STATE_DESTROY
}

export enum KeepAliveAppType {
    ALL = 0,
    THIRD_PARTY = 1,
    SYSTEM = 2
}

export enum KeepAliveSetter {
    SYSTEM = 0,
    USER = 1
}

export interface KeepAliveBundleInfo {
    bundleName: string;
    type: KeepAliveAppType;
    setter: KeepAliveSetter;
}

export class KeepAliveBundleInfoInner implements KeepAliveBundleInfo {
    bundleName: string = '';
    type: KeepAliveAppType = KeepAliveAppType.ALL;
    setter: KeepAliveSetter = KeepAliveSetter.SYSTEM;
}

export native function nativePreloadApplication(callback: AsyncCallbackWrapper<void>, bundleName: string, userId: number,
    mode: PreloadMode, appIndex?: number): void;
export function preloadApplication(bundleName: string, userId: number, mode: PreloadMode, appIndex?: number): Promise<void>{
   let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativePreloadApplication(myCall, bundleName, userId, mode, appIndex);
      });
    });
    return p;
}

export native function nativeGetRunningProcessInformation(callback: AsyncCallbackWrapper<Array<ProcessInformation>>): void;
export function getRunningProcessInformation(callback: AsyncCallback<Array<ProcessInformation>>): void {
   let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>(callback);
    taskpool.execute((): void => {
      appManager.nativeGetRunningProcessInformation(myCall);
    });
}

export function getRunningProcessInformation(): Promise<Array<ProcessInformation>> {
    let p = new Promise<Array<ProcessInformation>>((resolve:(data:Array<ProcessInformation>)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError<void>, data: Array<ProcessInformation>)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetRunningProcessInformation(myCall);
      });
    });
    return p;
}

export native function nativeGetForegroundApplications(callback:AsyncCallbackWrapper<Array<AppStateData>>): void;
export function getForegroundApplications(callback: AsyncCallback<Array<AppStateData>>): void {
    let myCall = new AsyncCallbackWrapper<Array<AppStateData>>(callback);
    taskpool.execute((): void => {
      appManager.nativeGetForegroundApplications(myCall);
    });
}

export function getForegroundApplications(): Promise<Array<AppStateData>> {
    let p = new Promise<Array<AppStateData>>((resolve:(data:Array<AppStateData>)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<AppStateData>>((err: BusinessError<void>, data: Array<AppStateData>)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetForegroundApplications(myCall);
      });
    });
    return p;
}

export native function nativeGetRunningMultiAppInfo(bundleName: string, callback: AsyncCallbackWrapper<RunningMultiAppInfo>): void;
export function getRunningMultiAppInfo(bundleName: string): Promise<RunningMultiAppInfo> {
    let p = new Promise<RunningMultiAppInfo>((resolve:(data: RunningMultiAppInfo)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<RunningMultiAppInfo>((err: BusinessError<void>, data: RunningMultiAppInfo)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetRunningMultiAppInfo(bundleName, myCall);
      });
    });
    return p;
}

export native function nativeGetRunningProcessInfoByBundleName(bundleName: string, callback:AsyncCallbackWrapper<Array<ProcessInformation>>):void;
export function getRunningProcessInfoByBundleName(bundleName: string, callback: AsyncCallback<Array<ProcessInformation>>): void  {
    let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>(callback);
    taskpool.execute((): void => {
      appManager.nativeGetRunningProcessInfoByBundleName(bundleName, myCall);
    });
}

export function getRunningProcessInfoByBundleName(bundleName: string): Promise<Array<ProcessInformation>> {
    let p = new Promise<Array<ProcessInformation>>((resolve:(data: Array<ProcessInformation>)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError<void>, data: Array<ProcessInformation>)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetRunningProcessInfoByBundleName(bundleName, myCall);
      });
    });
    return p;
}

export native function nativeGetRunningProcessInfoByBundleNameAndUserId(bundleName: string,
  userId: number, callback:AsyncCallbackWrapper<Array<ProcessInformation>>):void;
export function getRunningProcessInfoByBundleName(bundleName: string, userId: number, callback: AsyncCallback<Array<ProcessInformation>>): void {
    let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>(callback);
    taskpool.execute((): void => {
      appManager.nativeGetRunningProcessInfoByBundleNameAndUserId(bundleName, userId, myCall);
    });
}

export function getRunningProcessInfoByBundleName(bundleName: string, userId: number): Promise<Array<ProcessInformation>> {
    let p = new Promise<Array<ProcessInformation>>((resolve:(data: Array<ProcessInformation>)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError<void>, data: Array<ProcessInformation>)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetRunningProcessInfoByBundleNameAndUserId(bundleName, userId, myCall);
      });
    });
    return p;
}

export native function nativeOn(type: string, observer: ApplicationStateObserver, bundleNameList?: Array<string>) : number;
export native function nativeOn(type: string, observer: ApplicationStateObserver) : number;

export function on(type: 'applicationState', observer: ApplicationStateObserver): number {
  return appManager.nativeOn('applicationState', observer);
}

export function on(type: 'applicationState', observer: ApplicationStateObserver, bundleNameList: Array<string>): number {
  return appManager.nativeOn('applicationState', observer, bundleNameList);
}

export native function nativeOff(type:string, observerId: number, callback: AsyncCallbackWrapper<void>) : void;
export function off(type: 'applicationState', observerId: number, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      appManager.nativeOff(type, observerId, myCall);
    });
}

export function off(type: 'applicationState', observerId: number): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeOff(type, observerId, myCall);
      });
    });
    return p;
}

export native function nativeGetAppMemorySize(callback: AsyncCallbackWrapper<number>) : void;
export function getAppMemorySize(callback: AsyncCallback<number>): void
{
    let myCall = new AsyncCallbackWrapper<number>(callback);
    taskpool.execute((): void => {
      appManager.nativeGetAppMemorySize(myCall);
    });
}
export function getAppMemorySize(): Promise<number> {
    let p = new Promise<number>((resolve:(data:number)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<number>((err: BusinessError<void>, data: number)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeGetAppMemorySize(myCall);
      });
    });
    return p;
}

export native function nativeIsRamConstrainedDevice(callback: AsyncCallbackWrapper<boolean>) : void;
export function isRamConstrainedDevice(callback: AsyncCallback<boolean>): void {
    let myCall = new AsyncCallbackWrapper<boolean>(callback);
    taskpool.execute((): void => {
      appManager.nativeIsRamConstrainedDevice(myCall);
    });
}
export function isRamConstrainedDevice(): Promise<boolean> {
    let p = new Promise<boolean>((resolve:(data:boolean)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<boolean>((err: BusinessError<void>, data: boolean)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeIsRamConstrainedDevice(myCall);
      });
    });
    return p;
}

export native function nativeIsRunningInStabilityTest(callback: AsyncCallbackWrapper<boolean>) : void;
export function isRunningInStabilityTest(callback: AsyncCallback<boolean>): void {
    let myCall = new AsyncCallbackWrapper<boolean>(callback);
    taskpool.execute((): void => {
      appManager.nativeIsRunningInStabilityTest(myCall);
    });
}
export function isRunningInStabilityTest(): Promise<boolean> {
    let p = new Promise<boolean>((resolve:(data:boolean)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<boolean>((err: BusinessError<void>, data: boolean)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeIsRunningInStabilityTest(myCall);
      });
    });
    return p;
}

export native function nativeKillProcessesByBundleNameSync(bundleName: string, callback: AsyncCallbackWrapper<void>) : void;
export native function nativeKillProcessesByBundleName(callback: AsyncCallbackWrapper<void>, bundleName: string, clearPageStack: boolean, appIndex?: number) : void;
export function killProcessesByBundleName(bundleName: string, callback: AsyncCallback<void>) : void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      appManager.nativeKillProcessesByBundleNameSync(bundleName, myCall);
    });
}
export function killProcessesByBundleName(bundleName: string): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeKillProcessesByBundleNameSync(bundleName, myCall);
      });
    });
    return p;
}
export function killProcessesByBundleName(bundleName: string, clearPageStack: boolean, appIndex?: number): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        appManager.nativeKillProcessesByBundleName(myCall, bundleName, clearPageStack, appIndex);
      });
    });
    return p;
}

export native function nativeKillProcessWithAccountSync(bundleName: string, accountId: number, callback: AsyncCallbackWrapper<void>) : void;
export function killProcessWithAccount(bundleName: string, accountId: number, callback: AsyncCallback<void>): void {
  let myCall = new AsyncCallbackWrapper<void>(callback);
  taskpool.execute((): void => {
    appManager.nativeKillProcessWithAccountSync(bundleName, accountId, myCall);
  });
}
export function killProcessWithAccount(bundleName: string, accountId: number): Promise<void> {
  let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
      if (err.code == 0) {
        resolve(undefined);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeKillProcessWithAccountSync(bundleName, accountId, myCall);
    });
  });
  return p;
}
export native function nativeKillProcessWithAccount(callback: AsyncCallbackWrapper<void>,
  bundleName: string, accountId: number, clearPageStack: boolean, appIndex?: number) : void;
export function killProcessWithAccount(bundleName: string, accountId: number,
  clearPageStack: boolean, appIndex?: number): Promise<void>
{
  let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
      if (err.code == 0) {
        resolve(undefined);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeKillProcessWithAccount(myCall, bundleName, accountId, clearPageStack, appIndex);
    });
  });
  return p;
}

export native function nativeGetProcessMemoryByPid(pid: number, callback: AsyncCallbackWrapper<number>) : void;
export function getProcessMemoryByPid(pid: number, callback: AsyncCallback<number>): void {
  let myCall = new AsyncCallbackWrapper<number>(callback);
  taskpool.execute((): void => {
    appManager.nativeGetProcessMemoryByPid(pid, myCall);
  });
}
export function getProcessMemoryByPid(pid: number): Promise<number> {
  let p = new Promise<number>((resolve:(data:number)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<number>((err: BusinessError<void>, data: number)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeGetProcessMemoryByPid(pid, myCall);
    });
  });
  return p;
}

export native function nativeGetRunningProcessInformationByBundleType(bundleType: bundleManager.BundleType,
  callback: AsyncCallbackWrapper<Array<ProcessInformation>>) : void;
export function getRunningProcessInformationByBundleType(bundleType: bundleManager.BundleType): Promise<Array<ProcessInformation>>
{
  let p = new Promise<Array<ProcessInformation>>((resolve:(data:Array<ProcessInformation>)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError<void>, data: Array<ProcessInformation>)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeGetRunningProcessInformationByBundleType(bundleType, myCall);
    });
  });
  return p;
}

export native function nativeIsSharedBundleRunning(bundleName: string, versionCode: number, callback: AsyncCallbackWrapper<boolean>) : void;
export function isSharedBundleRunning(bundleName: string, versionCode: number, callback: AsyncCallback<boolean>): void {
  let myCall = new AsyncCallbackWrapper<boolean>(callback);
  taskpool.execute((): void => {
    appManager.nativeIsSharedBundleRunning(bundleName, versionCode, myCall);
  });
}
export function isSharedBundleRunning(bundleName: string, versionCode: number): Promise<boolean> {
  let p = new Promise<boolean>((resolve:(data:boolean)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<boolean>((err: BusinessError<void>, data: boolean)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeIsSharedBundleRunning(bundleName, versionCode, myCall);
    });
  });
  return p;
}

export native function nativeGetSupportedProcessCachePids(bundleName: string, callback: AsyncCallbackWrapper<Array<number>>) : void;
export function getSupportedProcessCachePids(bundleName: string): Promise<Array<number>> {
  let p = new Promise<Array<number>>((resolve:(data:Array<number>)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<Array<number>>((err: BusinessError<void>, data: Array<number>)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeGetSupportedProcessCachePids(bundleName, myCall);
    });
  });
  return p;
}

export native function nativeKillProcessesInBatch(pids: Array<number>, callback: AsyncCallbackWrapper<void>) : void;
export function killProcessesInBatch(pids: Array<number>) : Promise<void> {
  let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
      if (err.code == 0) {
        resolve(undefined);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeKillProcessesInBatch(pids, myCall);
    });
  });
  return p;
}

export native function nativeIsAppRunning(callback: AsyncCallbackWrapper<boolean>, bundleName: string, appCloneIndex?: number) : void;
export function isAppRunning(bundleName: string, appCloneIndex?: number): Promise<boolean> {
  let p = new Promise<boolean>((resolve:(data:boolean)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<boolean>((err: BusinessError<void>, data: boolean)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeIsAppRunning(myCall, bundleName, appCloneIndex);
    });
  });
  return p;
}

export native function nativeSetKeepAliveForBundle(bundleName: string,
  userId: number, enable: boolean, callback: AsyncCallbackWrapper<void>) : void;
export function setKeepAliveForBundle(bundleName: string, userId: number, enable: boolean): Promise<void> {
  let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
      if (err.code == 0) {
        resolve(undefined);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeSetKeepAliveForBundle(bundleName, userId, enable, myCall);
    });
  });
  return p;
}

export native function nativeGetKeepAliveBundles(callback: AsyncCallbackWrapper<Array<KeepAliveBundleInfo>>,
  type: KeepAliveAppType, userId?: number) : void;
export function getKeepAliveBundles(type: KeepAliveAppType, userId?: number): Promise<Array<KeepAliveBundleInfo>> {
  let p = new Promise<Array<KeepAliveBundleInfo>>((resolve:(data:Array<KeepAliveBundleInfo>)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<Array<KeepAliveBundleInfo>>((err: BusinessError<void>, data: Array<KeepAliveBundleInfo>)=>{
      if (err.code == 0) {
        resolve(data);
      } else {
        reject(err);
      }
    });
    taskpool.execute((): void => {
      appManager.nativeGetKeepAliveBundles(myCall, type, userId);
    });
  });
  return p;
}

} // namespace appManager
