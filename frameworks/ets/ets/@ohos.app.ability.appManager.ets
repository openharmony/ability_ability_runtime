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
import _AppStateData from 'application.AppStateData';
import hilog from '@ohos.hilog';
import { BusinessError, AsyncCallback } from '@ohos.base';
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace appManager {
loadLibraryWithPermissionCheck("app_manager_ani.z", "@ohos.app.ability.appManager")

export type ProcessInformation = _ProcessInformation;
export type AppStateData = _AppStateData;
export type RunningMultiAppInfo = _RunningMultiAppInfo;

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

export native function nativePreloadApplication(callback: AsyncCallbackWrapper<void>, bundleName: string, userId: number,
    mode: PreloadMode, appIndex?: number): void;
export function preloadApplication(bundleName: string, userId: number, mode: PreloadMode, appIndex?: number): Promise<void>{
   let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError | null)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
        if (err == null || err.code == 0) {
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
    let p = new Promise<Array<ProcessInformation>>((resolve:(data:Array<ProcessInformation>)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError | null, data: Array<ProcessInformation> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<ProcessInformation>);
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
    let p = new Promise<Array<AppStateData>>((resolve:(data:Array<AppStateData>)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<AppStateData>>((err: BusinessError | null, data: Array<AppStateData> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<AppStateData>);
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
    let p = new Promise<RunningMultiAppInfo>((resolve:(data: RunningMultiAppInfo)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<RunningMultiAppInfo>((err: BusinessError | null, data: RunningMultiAppInfo | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as RunningMultiAppInfo);
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
    let p = new Promise<Array<ProcessInformation>>((resolve:(data: Array<ProcessInformation>)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError | null, data: Array<ProcessInformation> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<ProcessInformation>);
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
    let p = new Promise<Array<ProcessInformation>>((resolve:(data: Array<ProcessInformation>)=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<Array<ProcessInformation>>((err: BusinessError | null, data: Array<ProcessInformation> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<ProcessInformation>);
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
} // namespace appManager
