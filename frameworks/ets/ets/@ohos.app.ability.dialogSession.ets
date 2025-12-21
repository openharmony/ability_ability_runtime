/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import AsyncCallbackWrapper from './utils/AbilityUtils';
import { BusinessError, AsyncCallback, RecordData } from '@ohos.base';
import { MultiAppMode } from 'bundleManager.ApplicationInfo';
import { MultiAppModeInner } from 'bundleManager.ApplicationInfoInner';
import Want from '@ohos.app.ability.Want';

export default namespace dialogSession {
  loadLibrary("dialog_session_ani_kit.z")

  export native function getDialogSessionInfo(dialogSessionId: string): DialogSessionInfo | null;
  export native function nativeSendDialogResult(dialogSessionId: string, targetWant: Want, isAllowed: boolean, callback: AsyncCallbackWrapper<void>): void;

  export interface DialogAbilityInfo {
    bundleName: string;
    moduleName: string;
    abilityName: string;
    abilityIconId: int;
    abilityLabelId: int;
    bundleIconId: int;
    bundleLabelId: int;
    visible: boolean;
    appIndex: int;
    multiAppMode: MultiAppMode;
    codePath?: string;
    installSource?: string;
  }

  export interface DialogSessionInfo {
    callerAbilityInfo: DialogAbilityInfo;
    targetAbilityInfos: Array<DialogAbilityInfo>;
    parameters?: Record<string, RecordData>;
  }

  export class DialogAbilityInfoInner implements DialogAbilityInfo {
    bundleName: string;
    moduleName: string;
    abilityName: string;
    abilityIconId: int;
    abilityLabelId: int;
    bundleIconId: int;
    bundleLabelId: int;
    visible: boolean;
    appIndex: int;
    multiAppMode: MultiAppMode;
    codePath?: string;
    installSource?: string;
  }

  export class DialogSessionInfoInner implements DialogSessionInfo {
    callerAbilityInfo: DialogAbilityInfo;
    targetAbilityInfos: Array<DialogAbilityInfo>;
    parameters?: Record<string, RecordData>;
  }

  export function sendDialogResult(dialogSessionId: string, targetWant: Want, isAllowed: boolean): Promise<void> {
    let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError | null)=>void):void => {
      let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
        if (err == null || err.code == 0) {
          resolve(undefined);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        dialogSession.nativeSendDialogResult(dialogSessionId, targetWant, isAllowed, myCall);
      });
    });
    return p;
  }

  export function sendDialogResult(dialogSessionId: string, targetWant: Want, isAllowed: boolean, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      dialogSession.nativeSendDialogResult(dialogSessionId, targetWant, isAllowed, myCall);
    });
  }
}