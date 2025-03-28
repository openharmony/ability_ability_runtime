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

import { AbilityInfo } from 'bundleManager.AbilityInfo';
import Want from '@ohos.app.ability.Want';
import StartOptions from '@ohos.app.ability.StartOptions';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { AbilityResult } from 'ability.abilityResult';
import AbilityStartCallback from 'application.AbilityStartCallback';
import { Configuration } from '@ohos.app.ability.Configuration';
import Context from 'application.Context';
import window from '@ohos.window';

export class AsyncCallbackWrapper<T> {
  myFun_:AsyncCallback<T, void> = (err: BusinessError<void>, data: T) => {}

  constructor(myFun:AsyncCallback<T, void>){
    console.log("AsyncCallbackWrapper");
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<void>, data: T) : void {
    this.myFun_(err, data);
  }
}

export default class UIAbilityContext extends Context {

  nativeContext : long;
  config: Configuration;
  abilityInfo: AbilityInfo;
  windowStage: window.WindowStage;

  private native nativeStartAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilitySync(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilityForResult(want: Want, callback:AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeStartAbilityForResult(want: Want, startOptions: StartOptions, callback:AsyncCallbackWrapper<AbilityResult>): void;
  private native nativeTerminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  private native nativeTerminateSelfWithResult(parameter: AbilityResult, callback:AsyncCallbackWrapper<void>): void;
  private native nativeReportDrawnCompletedSync(callback:AsyncCallbackWrapper<void>): void;
  private native nativeStartAbilityByTypeSync(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback): int;
  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    let p1 = launch this.nativeStartAbilitySync(want, myCall);
  }

  startAbility(want: Want, options: StartOptions, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    let p1 = launch this.nativeStartAbilitySync(want, options, myCall);
  }

  startAbility(want: Want): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      launch this.nativeStartAbilitySync(want, myCall);
    });
    return p;
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
      launch this.nativeStartAbilitySync(want, options, myCall);
    });
    return p;
  }

  startAbilityForResult(want: Want, callback: AsyncCallback<AbilityResult, void>): void {
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeStartAbilityForResult(want, myCall);
  }

  startAbilityForResult(want: Want, startOptions: StartOptions, callback: AsyncCallback<AbilityResult, void>): void {
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeStartAbilityForResult(want, startOptions, myCall);
  }

  startAbilityForResult(want: Want): Promise<AbilityResult>{
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError<void>, data: AbilityResult)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      launch this.nativeStartAbilityForResult(want, myCall);
    });
    return p;
  }

  startAbilityForResult(want: Want, startOptions: StartOptions): Promise<AbilityResult> {
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError<void>, data: AbilityResult)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      launch this.nativeStartAbilityForResult(want, startOptions, myCall);
    });
    return p;
  }

  terminateSelf(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeTerminateSelfSync(myCall);
  }

  terminateSelf(): Promise<void> {
    let p = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      launch this.nativeTerminateSelfSync(myCall);
    });
    return p;
  }

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeTerminateSelfWithResult(parameter, myCall);
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<void>{
    let p = new Promise<void>((resolve: (data: undefined)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      launch this.nativeTerminateSelfWithResult(parameter, myCall);
    });
    return p;
  }

  reportDrawnCompleted(callback:AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeReportDrawnCompletedSync(myCall);
  }

  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback, callback: AsyncCallback<void>): void {
    let p1 = taskpool.execute((): int => {
      return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
    });
    p1.then((e: NullishType) => {
      let retError = new BusinessError<void>();
      let resultCode: int = e as int;
      retError.code = resultCode;
      callback(retError, undefined);
    });
  }
 
  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback): Promise<void> {
    let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError<void>) => void): void => {
      let p1 = taskpool.execute((): int => {
        return this.nativeStartAbilityByTypeSync(type, wantParam, startCallback);
      });
      p1.then((e: NullishType) => {
        let retError = new BusinessError<void>();
        let resultCode: int = e as int;
        if (resultCode === 0) {
          resolve(undefined);
        } else {
          retError.code = resultCode;
          reject(retError);
        }
      });
    });
    return p;
  }
}
