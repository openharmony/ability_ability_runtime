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
import UIExtensionContext from 'application.UIExtensionContext';
import { AbilityUtils } from './utils/AbilityUtils';
import PhotoEditorExtensionContext from 'application.PhotoEditorExtensionContext';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';


export default class PhotoEditorExtensionAbility extends UIExtensionContext {
  // 异步回调相关
  private callOnDestroy(): boolean {
    let p = this.onDestroy();
    if (p instanceof Promise) {
      return true;
    }
    return false;
  }

  context: PhotoEditorExtensionContext = {};

  onCreate(): void {}

  onForeground(): void {}

  onBackground(): void {}

  onDestroy(): Promise<void> | undefined {
    return undefined;
  }

  onStartContentEditing(uri: string, want: Want, session: UIExtensionContentSession): void {}

}