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

import { AbilityInfo } from '../bundleManager/AbilityInfo';
import Want from '../@ohos.app.ability.Want';
import StartOptions from '../@ohos.app.ability.StartOptions';
import { BusinessError, AsyncCallback } from '../@ohos.base';
import { AbilityResult } from '../ability/abilityResult';
import AbilityStartCallback from './AbilityStartCallback';
import { Configuration } from '../@ohos.app.ability.Configuration';

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

export default class UIAbilityContext {

  public nativeContext : long;
  public config?: Configuration;
  public abilityInfo?: AbilityInfo;
  // public windowStage?: window.WindowStage;

  public native nativeStartAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  public native nativeStartAbilitySync(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;
  public native nativeStartAbilityForResult(want: Want, callback:AsyncCallbackWrapper<AbilityResult>): void;
  public native nativeStartAbilityForResult(want: Want, startOptions: StartOptions, callback:AsyncCallbackWrapper<AbilityResult>): void;
  public native nativeTerminateSelfSync(callback:AsyncCallbackWrapper<void>): void;
  public native nativeTerminateSelfWithResult(parameter: AbilityResult, callback:AsyncCallbackWrapper<void>): void;
  public native nativeReportDrawnCompletedSync(callback:AsyncCallbackWrapper<void>): void;
  public native nativeStartAbilityByTypeSync(type: string, wantParam: string, startCallback: AbilityStartCallback, callback:AsyncCallbackWrapper<void>): void;

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    console.log("call startAbility callback 111");
    let myCall = new AsyncCallbackWrapper<void>(callback);
    let p1 = launch this.nativeStartAbilitySync(want, myCall);
    console.log("call startAbility callback 222");
  }

  startAbility(want: Want, options: StartOptions, callback: AsyncCallback<void>): void {
    console.log("call startAbility callback 111");
    let myCall = new AsyncCallbackWrapper<void>(callback);
    let p1 = launch this.nativeStartAbilitySync(want, options, myCall);
    console.log("call startAbility callback 222");
  }

  startAbility(want: Want): Promise<int> {
    let p = new Promise<int>((resolve: (data:int)=>void, reject:(err: BusinessError<void>)=>void):void => {
    let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(1);
        } else {
          reject(err);
        }
      });
      launch this.nativeStartAbilitySync(want, myCall);
    });
    return p;
  }

  startAbility(want: Want, options: StartOptions): Promise<int> {
    console.log("call startAbility callback 111");
    let p = new Promise<int>((resolve: (data:int)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(1);
        } else {
          reject(err);
        }
      });
      launch this.nativeStartAbilitySync(want, options, myCall);
      console.log("call startAbility callback 222");
    });
    return p;
  }

  startAbilityForResult(want: Want, callback: AsyncCallback<AbilityResult, void>): void {
    console.log("call startAbilityForResult callback 111");
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeStartAbilityForResult(want, myCall);
    console.log("call startAbilityForResult callback 222");
  }

  startAbilityForResult(want: Want, startOptions: StartOptions, callback: AsyncCallback<AbilityResult, void>): void {
    console.log("call startAbilityForResult callback 111");
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeStartAbilityForResult(want, startOptions, myCall);
    console.log("call startAbilityForResult callback 222");
  }

  startAbilityForResult(want: Want): Promise<AbilityResult>{
    console.log("call startAbilityForResult callback 111");
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
    console.log("call startAbilityForResult callback 222");
    return p;
  }

  startAbilityForResult(want: Want, startOptions: StartOptions): Promise<AbilityResult> {
    console.log("call startAbilityForResult callback 111");
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
    console.log("call startAbilityForResult callback 222");
    return p;
  }

  terminateSelf(callback:AsyncCallback<void>): void {
    console.log("reportDrawnCompleted callback 111");
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeTerminateSelfSync(myCall);
    console.log("reportDrawnCompleted callback 222");
  }

  terminateSelf(): Promise<int> {
    console.log("call startAbility callback 111");
    let p = new Promise<int>((resolve: (data:int)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(1);
        } else {
          reject(err);
        }
      });
      launch this.nativeTerminateSelfSync(myCall);
      console.log("call startAbility callback 222");
    });
    return p;
  }

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<void>): void {
    console.log("call terminateSelfWithResult callback 111");
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeTerminateSelfWithResult(parameter, myCall);
    console.log("call terminateSelfWithResult callback 222");
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<int>{
    console.log("call terminateSelfWithResult callback 111");
    let p = new Promise<int>((resolve: (data: int)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve(1);
        } else {
          reject(err);
        }
      });
      launch this.nativeTerminateSelfWithResult(parameter, myCall);
    });
    console.log("call terminateSelfWithResult callback 222");
    return p;
  }

  reportDrawnCompleted(callback:AsyncCallback<void>): void {
    console.log("reportDrawnCompleted callback 111");
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeReportDrawnCompletedSync(myCall);
    console.log("reportDrawnCompleted callback 222");
  }

  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback, callback: AsyncCallback<void>): void {
    console.log("call startAbilityByType callback 111");
    let jsonStr = ""; //convert form value;
    let myCall = new AsyncCallbackWrapper<void>(callback);
    launch this.nativeStartAbilityByTypeSync(type, jsonStr, startCallback, myCall);
    console.log("call startAbilityByType callback 222");
  }
 
  startAbilityByType(type: string, wantParam: Record<string, Object>, startCallback: AbilityStartCallback): Promise<void> {
    console.log("call startAbilityByType promis type 111..");
    let p = new Promise<void>((resolve: ()=>void, reject:(err: BusinessError)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError)=>{
        console.log("call startAbilityByType promis type callback 122");
        if (err.code == 0) {
          resolve();
        } else {
          reject(err);
        }
      });
      let jsonStr = ""; //convert form value;
      launch this.nativeStartAbilityByTypeSync(type, jsonStr, startCallback, myCall);
    });
    console.log("call startAbilityByType callback end...");
    return p;
  }
}
