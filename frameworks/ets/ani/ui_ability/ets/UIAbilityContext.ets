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

import Want from './@ohos.app.ability.Want';
import StartOptions from './@ohos.app.ability.StartOptions';
import { BusinessError, AsyncCallback } from './@ohos.base';
import { AbilityResult } from './abilityResult';

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

export namespace ConfigurationConstant {
  export enum ColorMode {
    COLOR_MODE_NOT_SET = -1,
    COLOR_MODE_DARK = 0,
    COLOR_MODE_LIGHT = 1
  }
  export enum Direction {
    DIRECTION_NOT_SET = -1,
    DIRECTION_VERTICAL = 0,
    DIRECTION_HORIZONTAL = 1
  }
  export enum ScreenDensity {
    SCREEN_DENSITY_NOT_SET = 0,
    SCREEN_DENSITY_SDPI = 120,
    SCREEN_DENSITY_MDPI = 160,
    SCREEN_DENSITY_LDPI = 240,
    SCREEN_DENSITY_XLDPI = 320,
    SCREEN_DENSITY_XXLDPI = 480,
    SCREEN_DENSITY_XXXLDPI = 640
  }
}
export class Configuration {
  language?: string;
  colorMode?: ConfigurationConstant.ColorMode;
  direction?: ConfigurationConstant.Direction;
  screenDensity?: ConfigurationConstant.ScreenDensity;
  displayId: int;
  hasPointerDevice: boolean;
  fontId?: string;
  fontSizeScale: double;
  fontWeightScale: double;
  mcc?: string;
  mnc?: string;
}

interface AbilityInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly name: string;
  readonly label: string;
  readonly labelId: int;
  readonly description: string;
  readonly descriptionId: int;
  readonly icon: string;
  readonly iconId: int;
  readonly process: string;
  readonly exported: boolean;
  // readonly type: bundleManager.AbilityType;
  // readonly orientation: bundleManager.DisplayOrientation;
  // readonly launchType: bundleManager.LaunchType;
  readonly permissions: Array<string>;
  readonly readPermission: string;
  readonly writePermission: string;
  readonly uri: string;
  readonly deviceTypes: Array<string>;
  // readonly applicationInfo: ApplicationInfo;
  // readonly metadata: Array<Metadata>;
  readonly enabled: boolean;
  // readonly supportWindowModes: Array<bundleManager.SupportWindowMode>;
  // readonly windowSize: WindowSize;
  readonly excludeFromDock: boolean;
  // readonly skills: Array<Skill>;
  readonly appIndex: int;
  readonly orientationId: int;
}

class AbilityInfoCls implements AbilityInfo {
  readonly bundleName: string = '';
  readonly moduleName: string = '';
  readonly name: string = '';
  readonly label: string = '';
  readonly labelId: int;
  readonly description: string = '';
  readonly descriptionId: int;
  readonly icon: string = '';
  readonly iconId: int;
  readonly process: string = '';
  readonly exported: boolean;
  readonly permissions: Array<string> = new Array<string>();
  readonly readPermission: string = '';
  readonly writePermission: string = '';
  readonly uri: string = '';
  readonly deviceTypes: Array<string> = new Array<string>();
  readonly enabled: boolean;
  readonly excludeFromDock: boolean;
  readonly appIndex: int;
  readonly orientationId: int;
}

export class UIAbilityContext {

  public nativeContext : long;
  public config?: Configuration;
  public abilityInfo?: AbilityInfo;
  // public windowStage?: window.WindowStage;

  public native nativeStartAbilitySync(want: Want, callback: AsyncCallbackWrapper<void>): void;
  public native nativeStartAbilitySync(want: Want, options: StartOptions, callback:AsyncCallbackWrapper<void>): void;
  public native nativeStartAbilityForResult(want: Want, callback:AsyncCallbackWrapper<AbilityResult>): void;
  public native nativeStartAbilityForResult(want: Want, startOptions: StartOptions, callback:AsyncCallbackWrapper<AbilityResult>): void;
  public native nativeTerminateSelfWithResult(parameter: AbilityResult, callback:AsyncCallbackWrapper<AbilityResult>): void;
  public native reportDrawnCompletedSync(): void;

  // startAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;
  startAbility(want: Want, callback: AsyncCallbackWrapper<void>):void{
    console.log("call startAbility callback 111");
    let p1 = launch this.nativeStartAbilitySync(want, callback);
    console.log("call startAbility callback 222");
  }

  // startAbility(want: Want, options: StartOptions, callback: AsyncCallbackWrapper<void>): void;
  startAbility(want: Want, options: StartOptions, callback: AsyncCallbackWrapper<void>):void{
    console.log("call startAbility callback 111");
    let p1 = launch this.nativeStartAbilitySync(want, options, callback);
    console.log("call startAbility callback 222");
  }

  // startAbility(want: Want, options?: StartOptions): Promise<void>;
  startAbility(want: Want, options?: StartOptions): Promise<void> {
    console.log("call startAbility callback 111");
    let p = new Promise<void>((resolve: ()=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>)=>{
        if (err.code == 0) {
          resolve();
        } else {
          reject(err);
        }
      });
      if (options) {
        launch this.nativeStartAbilitySync(want, options, myCall);
      } else {
        launch this.nativeStartAbilitySync(want, myCall);
      }
    console.log("call startAbility callback 222");
    });
    return p;
  }

  startAbilityForResult(want: Want, callback: AsyncCallback<AbilityResult, void>):void{
    console.log("call startAbilityForResult callback 111");
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeStartAbilityForResult(want, myCall);
    console.log("call startAbilityForResult callback 222");
  }

  startAbilityForResult(want: Want, startOptions: StartOptions, callback: AsyncCallback<AbilityResult, void>):void{
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

  startAbilityForResult(want: Want, startOptions: StartOptions): Promise<AbilityResult>{
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

  terminateSelfWithResult(parameter: AbilityResult, callback: AsyncCallback<AbilityResult, void>): void{
    
    console.log("call terminateSelfWithResult callback 111");
    let myCall = new AsyncCallbackWrapper<AbilityResult>(callback);
    launch this.nativeTerminateSelfWithResult(parameter, myCall);
    console.log("call terminateSelfWithResult callback 222");
  }

  terminateSelfWithResult(parameter: AbilityResult): Promise<AbilityResult>{
    console.log("call terminateSelfWithResult callback 111");
    let p = new Promise<AbilityResult>((resolve: (data: AbilityResult)=>void, reject:(err: BusinessError<void>)=>void):void => {
      let myCall = new AsyncCallbackWrapper<AbilityResult>((err: BusinessError<void>, data: AbilityResult)=>{
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      launch this.nativeTerminateSelfWithResult(parameter, myCall);
    });
    console.log("call terminateSelfWithResult callback 222");
    return p;
  }

  reportDrawnCompleted(callback:() => void): void {
    console.log("reportDrawnCompleted callback 111");
    let p1 = launch this.reportDrawnCompletedSync();
    console.log("reportDrawnCompleted callback 222");
    p1?.then<void>(():void=>{
      //callback();
      console.log("reportDrawnCompleted callback 333");
    });
    console.log("reportDrawnCompleted callback 444");
  }
}
