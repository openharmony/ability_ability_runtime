/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
 
// import type { AbilityResult } from './ability/abilityResult';
// import type AbilityStartCallback from './application/AbilityStartCallback';
import type { AsyncCallback } from './@ohos.base';
import  { BusinessError } from './@ohos.base';
// import type Want from './@ohos.app.ability.Want';
// import type StartOptions from './@ohos.app.ability.StartOptions';
import type uiExtensionHost from './@ohos.uiExtensionHost';
// import type uiExtension from './@ohos.arkui.uiExtension';
import type LocalStorage from './LocalStorage';

class UIExtensionContentSession {
  
  static {loadLibrary("sts_ui_extension_content_session.z");}

  native sendData(data: Record<string, Object>): void;
  native loadContent(path: string, storage?: LocalStorage): void;
  native setWindowBackgroundColor(color: string): void;
  native getUIExtensionHostWindowProxy(): uiExtensionHost.UIExtensionHostWindowProxy;
  native setReceiveDataCallbackSync(): void;
  native terminateSelfSync(): void;

  terminateSelf( callback: AsyncCallback<void>):void{
    console.log("ability.finishTest terminateSelfSync start");
       let p1 = launch this.terminateSelfSync();
    console.log("ability.finishTest terminateSelfSync end");
           p1.then((e :NullishType)=>{
             console.log("ability.finishTest terminateSelfSync");
             let resultCode: Int  = 1;
             let r: BusinessError = { code: resultCode.intValue(), data: undefined };
               callback(r, undefined);
           }, (err:Object): void => {
           });
   }
   terminateSelf():Promise<void>{
     let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Object) => void) => {
         let p1 = launch this.terminateSelfSync();
         p1.then((e :NullishType)=>{
           let PromiseLike = e as PromiseLike<void>;
           resolve(PromiseLike);
         }, (err:Object): void => {
         });
     });
     return p;
   }

   setReceiveDataCallback(callback: (data: Record<string, Object>) => void): void{
     let p1 = launch this.setReceiveDataCallbackSync();
         p1.then((e :NullishType)=>{
            let result = e as Record<string, Object>;
              callback(result);
         }, (err:Object): void => {
         });
   }
}