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

import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import UIExtensionContext from 'application.UIExtensionContext';
import { AbilityUtils } from './utils/AbilityUtils';

export default class UIExtensionAbility extends ExtensionAbility {

  private destroyCallbackPoint: long;
  private native nativeOnDestroyCallback(): void;
  private callOnDestroy(): boolean {
    const derivedClassType = AbilityUtils.getClassType(this);
    if (derivedClassType === undefined) {
      this.onDestroy();
      return false;
    }
    const uiExtensionAbilityClassType = AbilityUtils.getClassType(new UIExtensionAbility());
    if (uiExtensionAbilityClassType === undefined) {
      this.onDestroy();
      return false;
    }
    if (AbilityUtils.isOverride(derivedClassType, "onDestroyAsync", uiExtensionAbilityClassType)) {
      this.onDestroyAsync().then(() => this.nativeOnDestroyCallback());
      return true;
    }
    this.onDestroy();
    return false;
  }

  context: UIExtensionContext = {};

  onCreate(launchParam: AbilityConstant.LaunchParam): void {}

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {}

  onSessionDestroy(session: UIExtensionContentSession): void {}

  onForeground(): void {}

  onBackground(): void {}

  onDestroy(): void {}

  onDestroyAsync(): Promise<void> {
    return new Promise<void>((resolve: (a: undefined)=>void, reject: (err: Error)=>void): void => {});
  }
}
