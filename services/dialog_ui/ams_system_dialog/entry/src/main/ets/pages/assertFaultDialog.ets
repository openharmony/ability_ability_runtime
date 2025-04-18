/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import abilityManager from '@ohos.app.ability.abilityManager';
import type { BusinessError } from '@ohos.base';
import type UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';

let storage = LocalStorage.GetShared();
const TAG: string = 'AssertFaultDialog_Page';
const DEBUG_ASSERT_RESULT: string = 'assertResult';

@Entry(storage)
@Component
struct AssertFaultDialog {
  @State private textDetail: string = '';

  aboutToAppear() {
    console.info(TAG, 'dialog page appears');
    this.textDetail = storage.get<string>('textDetail');
  }

  existApp() {
    console.info(TAG, 'Exist app called');
    try {
      AppStorage.setOrCreate(DEBUG_ASSERT_RESULT, abilityManager.UserStatus.ASSERT_TERMINATE);
      storage.get<UIExtensionContentSession>('session').terminateSelf().then(() => {
        console.log(TAG, 'terminateSelf success.');
      }).catch((err: BusinessError) => {
        console.error(TAG, `terminateSelf failed, error: ${JSON.stringify(err)}`);
      })
    } catch (error) {
      console.error(TAG, `try notifyDebugAssertResult failed, error: ${JSON.stringify(error)}`);
    }
  }

  onContinueCall() {
    console.info(TAG, 'On continue called');
    try {
      AppStorage.setOrCreate(DEBUG_ASSERT_RESULT, abilityManager.UserStatus.ASSERT_CONTINUE);
      storage.get<UIExtensionContentSession>('session').terminateSelf().then(() => {
        console.log(TAG, 'terminateSelf success.');
      }).catch((err: BusinessError) => {
        console.error(TAG, `terminateSelf failed, error: ${JSON.stringify(err)}`);
      })
    } catch (error) {
      console.error(TAG, `try notifyDebugAssertResult failed, error: ${JSON.stringify(error)}`);
    }
  }

  onRetryCall() {
    console.info(TAG, 'On retry called');
    try {
      AppStorage.setOrCreate(DEBUG_ASSERT_RESULT, abilityManager.UserStatus.ASSERT_RETRY);
      storage.get<UIExtensionContentSession>('session').terminateSelf().then(() => {
        console.log(TAG, 'terminateSelf success.');
      }).catch((err: BusinessError) => {
        console.error(TAG, `terminateSelf failed, error: ${JSON.stringify(err)}`);
      })
    } catch (error) {
      console.error(TAG, `try notifyDebugAssertResult failed, error: ${JSON.stringify(error)}`);
    }
  }

  onTerminationCall() {
    console.info(TAG, 'On termination called');
    try {
      AppStorage.setOrCreate(DEBUG_ASSERT_RESULT, abilityManager.UserStatus.ASSERT_TERMINATE);
      storage.get<UIExtensionContentSession>('session').terminateSelf().then(() => {
        console.log(TAG, 'terminateSelf success.');
      }).catch((err: BusinessError) => {
        console.error(TAG, `terminateSelf failed, error: ${JSON.stringify(err)}`);
      })
    } catch (error) {
      console.error(TAG, `try notifyDebugAssertResult failed, error: ${JSON.stringify(error)}`);
    }
  }

  build() {
    Column(
      AlertDialog.show(
        {
          title: 'Assert Fault Dialog',
          message: this.textDetail,
          autoCancel: false,
          alignment: DialogAlignment.Center,
          gridCount: 4,
          buttonDirection: DialogButtonDirection.HORIZONTAL,
          cancel: this.existApp,
          buttons: [
            {
              enabled: true,
              defaultFocus: false,
              style: DialogButtonStyle.HIGHLIGHT,
              value: $r('app.string.button_continue'),
              fontColor: $r('sys.color.ohos_id_color_foreground_contrary'),
              backgroundColor: $r('app.color.button_color'),
              action: this.onContinueCall
            },
            {
              enabled: true,
              defaultFocus: false,
              style: DialogButtonStyle.HIGHLIGHT,
              value: $r('app.string.button_retry'),
              fontColor: $r('sys.color.ohos_id_color_foreground_contrary'),
              backgroundColor: $r('app.color.button_color'),
              action: this.onRetryCall
            },
            {
              enabled: true,
              defaultFocus: true,
              style: DialogButtonStyle.HIGHLIGHT,
              value: $r('app.string.button_termination'),
              fontColor: $r('sys.color.ohos_id_color_foreground_contrary'),
              backgroundColor: $r('app.color.button_color'),
              action: this.onTerminationCall
            }
          ]
        }
      )
    ) {}
  }
}
