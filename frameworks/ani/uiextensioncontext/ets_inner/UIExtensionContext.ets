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
/**
 * @file
 * @kit AbilityKit
 */

// import { AbilityResult } from '../ability/abilityResult';
import type { AsyncCallback } from '../@ohos.base';
import { BusinessError } from '../@ohos.base';
// import ConnectOptions from '../ability/connectOptions';
// import ExtensionContext from './ExtensionContext';
// import type Want from '../@ohos.app.ability.Want';
// import type StartOptions from '../@ohos.app.ability.StartOptions';
// import type AtomicServiceOptions from '../@ohos.app.ability.AtomicServiceOptions';
// import OpenLinkOptions from '../@ohos.app.ability.OpenLinkOptions';
// import type ConfigurationConstant from '../@ohos.app.ability.ConfigurationConstant';
// import type UIServiceProxy from './UIServiceProxy';
// import type UIServiceExtensionConnectCallback from './UIServiceExtensionConnectCallback';

class UIExtensionContext {
  public nativeUIExtensionContext:long = 0;
  public native  terminateSelfSync( ): void;
  public native  terminateSelfSyncPromise( ): void;
    terminateSelf(callback: AsyncCallback<void>):void{
      console.log("UIExtensionContext.terminateSelf callback1");
    let p1 = launch this.terminateSelfSync();
    console.log("UIExtensionContext.terminateSelf callback2");
        p1.then((e :NullishType)=>{
          console.log("UIExtensionContext.terminateSelf callback3");
          let resultCode: Int  = e as Int;
          console.log("UIExtensionContext.terminateSelf callback4");
          let r: BusinessError = { code: resultCode.intValue(), data: undefined };
          console.log("UIExtensionContext.terminateSelf callback5");
            callback(r, undefined);
            console.log("UIExtensionContext.terminateSelf callback6");
        }, (err:Object): void => {
          console.log("UIExtensionContext.terminateSelf callback7");
        });
    }
    terminateSelf( ):Promise<void>{
      console.log("UIExtensionContext.terminateSelf promise1");
      let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
        console.log("UIExtensionContext.terminateSelf promise2");
          let p1 = launch this.terminateSelfSyncPromise();
          console.log("UIExtensionContext.terminateSelf promise3");
          p1.then((e :NullishType)=>{
            console.log("UIExtensionContext.terminateSelf promise4");
            let PromiseLike = e as PromiseLike<void>;
            resolve(PromiseLike);
          }, (err:Object): void => {
            console.log("UIExtensionContext.terminateSelf promise5");
          });
      });
      return p;
    }
}