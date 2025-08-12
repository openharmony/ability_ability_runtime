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

import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import ConfigurationConstant from '@ohos.app.ability.ConfigurationConstant';
import UIAbility from '@ohos.app.ability.UIAbility';
import hilog from '@ohos.hilog';
import { BusinessError } from '@kit.BasicServicesKit';
import window from '@ohos.window';

const DOMAIN = 0x1323;
const TAG = 'InsightIntents';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    this.context.getApplicationContext().setColorMode(ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET);
    AppStorage.setAndLink('context', this.context);
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onCreate');
    const callerBundleName: string | undefined = want.parameters?.['ohos.aafwk.param.callerBundleName']?.toString();
    if (callerBundleName === undefined || callerBundleName !== 'com.huawei.hmos.aidataservice') {
      try {
        this.context.terminateSelf();
      } catch (err) {
        hilog.error(DOMAIN, TAG, 'Failed to context.terminateSelf. Cause: %{public}s', JSON.stringify(err));
      } 
    }
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'Succeeded in loading the content.');
      try {
        windowStage.getMainWindow((err, data) => {
          data.setWindowLayoutFullScreen(true).then(() => {
            hilog.info(DOMAIN, TAG, 'Succeeded in setting the window layout to full-screen mode.');
          }).catch((err:BusinessError) => {
            hilog.error(DOMAIN, TAG, 'Failed to set the window layout to full-screen mode. Cause: %{public}s', JSON.stringify(err));
          })
          data.setWindowSystemBarProperties({
            navigationBarColor: '#F1F3F5',
            statusBarColor: '#F1F3F5'
          }).then(() => {
            hilog.info(DOMAIN, TAG, 'Succeeded in setting the system bar properties.');
          }).catch((err: BusinessError) => {
            hilog.error(DOMAIN, TAG, 'Failed to set the system bar properties. Cause: %{public}s', JSON.stringify(err));
          })
        });
      } catch (err) {
        hilog.error(DOMAIN, TAG, 'Failed to getMainWindow. Cause: %{public}s', JSON.stringify(err));
      }
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onBackground');
  }
}