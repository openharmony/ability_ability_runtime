/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import AsyncCallbackWrapper from './utils/AbilityUtils';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { BusinessAbilityInfo as _BusinessAbilityInfo } from 'application.BusinessAbilityInfo';

export default namespace businessAbilityRouter {
  loadLibrary("businessabilityrouter_ani.z")
  export enum BusinessType {
    SHARE = 0,
    UNSPECIFIED = 255
  }
  export interface BusinessAbilityFilter {
    businessType: BusinessType;
    mimeType?: string;
    uri?: string;
  }

  export class BusinessAbilityFilterImpl implements BusinessAbilityFilter {
    businessType: BusinessType;
    mimeType?: string;
    uri?: string;
  }

  export native function nativeQueryBusinessAbilityInfos(filter: BusinessAbilityFilter,
    callback: AsyncCallbackWrapper<Array<BusinessAbilityInfo>>): void;

  export function queryBusinessAbilityInfo(filter: BusinessAbilityFilter,
    callback: AsyncCallback<Array<BusinessAbilityInfo>, void>): void {
    let myCall = new AsyncCallbackWrapper<Array<BusinessAbilityInfo>>(callback);
    taskpool.execute((): void => {
      businessAbilityRouter.nativeQueryBusinessAbilityInfos(filter, myCall);
    });
  }

  export function queryBusinessAbilityInfo(filter: BusinessAbilityFilter): Promise<Array<BusinessAbilityInfo>> {
    let p = new Promise<Array<BusinessAbilityInfo>>((resolve: (data: Array<BusinessAbilityInfo>) => void,
    reject: (err: BusinessError) => void): void => {
      let myCall = new AsyncCallbackWrapper<Array<BusinessAbilityInfo>>((err: BusinessError | null,
        data: Array<BusinessAbilityInfo> | undefined)=>{
        if (err == null || err.code == 0) {
          resolve(data as Array<BusinessAbilityInfo>);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        businessAbilityRouter.nativeQueryBusinessAbilityInfos(filter, myCall);
      }).catch((err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export type BusinessAbilityInfo = _BusinessAbilityInfo;
}