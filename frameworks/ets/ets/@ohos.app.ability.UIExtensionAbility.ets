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
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import UIExtensionContext from 'application.UIExtensionContext';

class ExtensionAbility{}

export default class UIExtensionAbility extends ExtensionAbility {

  private isOnDestroyAsync: boolean = true;
  private destroyCallbackPoint: long;
  private native nativeOnDestroyCallback(): void;
  private callOnDestroy(): boolean {
    let p = this.onDestroyAsync();
    if (this.isOnDestroyAsync) {
      p.then<void>((): void => {
        this.nativeOnDestroyCallback();
      });
    } else {
      this.onDestroy();
    }
    return this.isOnDestroyAsync;
  }

  context: UIExtensionContext = {};

  onCreate(launchParam: AbilityConstant.LaunchParam): void {}

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {}

  onSessionDestroy(session: UIExtensionContentSession): void {}

  onForeground(): void {}

  onBackground(): void {}

  onDestroy(): void {}

  onDestroyAsync(): Promise<void> {
    this.isOnDestroyAsync = false;
    return new Promise<void>((resolve: (a: undefined)=>void, reject: (err: Error)=>void): void => {});
  }
}
