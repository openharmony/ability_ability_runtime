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

import { ApplicationInfo } from 'bundleManager.ApplicationInfo'
import { ApplicationInfoInner } from 'bundleManager.ApplicationInfoInner';
import businessAbilityRouter from '@ohos.app.businessAbilityRouter'

export interface BusinessAbilityInfo {
  readonly bundleName: string;
  readonly moduleName: string;
  readonly name: string;
  readonly labelId: int;
  readonly descriptionId: int;
  readonly iconId: int;
  readonly businessType: businessAbilityRouter.BusinessType;
  readonly applicationInfo: ApplicationInfo;
}

export class BusinessAbilityInfoInner implements BusinessAbilityInfo {
  readonly bundleName: string = '';
  readonly moduleName: string = '';
  readonly name: string = '';
  readonly labelId: int;
  readonly descriptionId: int;
  readonly iconId: int;
  readonly businessType: businessAbilityRouter.BusinessType = businessAbilityRouter.BusinessType.UNSPECIFIED;
  readonly applicationInfo: ApplicationInfo = new ApplicationInfoInner;
}