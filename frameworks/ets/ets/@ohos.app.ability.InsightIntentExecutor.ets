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

import window from '@ohos.window';
import insightIntent from './@ohos.app.ability.insightIntent';
import InsightIntentContext from '@ohos.app.ability.InsightIntentContext';
import type UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';

export default class InsightIntentExecutor {
  context: InsightIntentContext = {};
  public nativeExecutor: long = 0;
  public isOnExecuteInUIAbilityForegroundModeAsync: boolean = true;
  public isOnExecuteInUIAbilityBackgroundModeAsync: boolean = true;
  public isOnExecuteInUIExtensionAbilityAsync: boolean = true;
  public isOnExecuteInServiceExtensionAbilityAsync: boolean = true;

  public native nativeOnExecuteResult(data: insightIntent.ExecuteResult): void;

  public callOnExecuteInUIAbilityForegroundMode(name: string, param: Record<string, Object>,
    pageLoader: window.WindowStage): insightIntent.ExecuteResult {
    let p = this.onExecuteInUIAbilityForegroundMode(name, param, pageLoader);
    if (p instanceof Promise) {
      this.isOnExecuteInUIAbilityForegroundModeAsync = true;
      p.then((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      this.isOnExecuteInUIAbilityForegroundModeAsync = false;
      return p;
    }
  }

  public callOnExecuteInUIAbilityBackgroundMode(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let p = this.onExecuteInUIAbilityBackgroundMode(name, param);
    if (p instanceof Promise) {
      this.isOnExecuteInUIAbilityBackgroundModeAsync = true;
      p.then<void>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      this.isOnExecuteInUIAbilityBackgroundModeAsync = false;
      return p;
    }
  }

  public callOnExecuteInUIExtensionAbility(name: string, param: Record<string, Object>,
    pageLoader: UIExtensionContentSession): insightIntent.ExecuteResult {
    let p = this.onExecuteInUIExtensionAbility(name, param, pageLoader);
    if (p instanceof Promise) {
      this.isOnExecuteInUIExtensionAbilityAsync = true;
      p.then<void>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      this.isOnExecuteInUIExtensionAbilityAsync = false;
      return p;
    }
  }

  public callOnExecuteInServiceExtensionAbility(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let p = this.onExecuteInServiceExtensionAbility(name, param);
    if (p instanceof Promise) {
      this.isOnExecuteInServiceExtensionAbilityAsync = true;
      p.then<void>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      this.isOnExecuteInServiceExtensionAbilityAsync = false;
      return p;
    }
  }

  onExecuteInUIAbilityForegroundMode(name: string, param: Record<string, Object>, pageLoader: window.WindowStage):
    insightIntent.ExecuteResult | Promise<insightIntent.ExecuteResult> {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInUIAbilityBackgroundMode(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult | Promise<insightIntent.ExecuteResult> {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInUIExtensionAbility(name: string, param: Record<string, Object>, pageLoader: UIExtensionContentSession):
    insightIntent.ExecuteResult | Promise<insightIntent.ExecuteResult> {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInServiceExtensionAbility(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult | Promise<insightIntent.ExecuteResult> {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }
}