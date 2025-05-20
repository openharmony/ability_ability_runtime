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
    let p = this.onExecuteInUIAbilityForegroundModeAsync(name, param, pageLoader);
    if (this.isOnExecuteInUIAbilityForegroundModeAsync) {
      p.then((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      return this.onExecuteInUIAbilityForegroundMode(name, param, pageLoader);
    }
  }

  public callOnExecuteInUIAbilityBackgroundMode(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let p = this.onExecuteInUIAbilityBackgroundModeAsync(name, param);
    if (this.isOnExecuteInUIAbilityBackgroundModeAsync) {
      p.then<insightIntent.ExecuteResult>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      return this.onExecuteInUIAbilityBackgroundMode(name, param);
    }
  }

  public callOnExecuteInUIExtensionAbility(name: string, param: Record<string, Object>,
    pageLoader: UIExtensionContentSession): insightIntent.ExecuteResult {
    let p = this.onExecuteInUIExtensionAbilityAsync(name, param, pageLoader);
    if (this.isOnExecuteInUIExtensionAbilityAsync) {
      p.then<insightIntent.ExecuteResult>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      return this.onExecuteInUIExtensionAbility(name, param, pageLoader);
    }
  }

  public callOnExecuteInServiceExtensionAbility(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let p = this.onExecuteInServiceExtensionAbilityAsync(name, param);
    if (this.isOnExecuteInServiceExtensionAbilityAsync) {
      p.then<insightIntent.ExecuteResult>((result: insightIntent.ExecuteResult): void => {
        this.nativeOnExecuteResult(result);
      });
      let ret: insightIntent.ExecuteResult = {};
      return ret;
    } else {
      return this.onExecuteInServiceExtensionAbility(name, param);
    }
  }

  onExecuteInUIAbilityForegroundMode(name: string, param: Record<string, Object>, pageLoader: window.WindowStage):
    insightIntent.ExecuteResult {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInUIAbilityForegroundModeAsync(name: string, param: Record<string, Object>, pageLoader: window.WindowStage):
    Promise<insightIntent.ExecuteResult> {
    this.isOnExecuteInUIAbilityForegroundModeAsync = false;
    return new Promise<insightIntent.ExecuteResult>((
      resolve: (a: insightIntent.ExecuteResult) => void,
      reject: (err: Error) => void): void => {
    });
  }

  onExecuteInUIAbilityBackgroundMode(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInUIAbilityBackgroundModeAsync(name: string, param: Record<string, Object>):
    Promise<insightIntent.ExecuteResult> {
    this.isOnExecuteInUIAbilityBackgroundModeAsync = false;
    return new Promise<insightIntent.ExecuteResult>((
      resolve: (a: insightIntent.ExecuteResult) => void,
      reject: (err: Error) => void): void => {
    });
  }

  onExecuteInUIExtensionAbility(name: string, param: Record<string, Object>, pageLoader: UIExtensionContentSession):
    insightIntent.ExecuteResult {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInUIExtensionAbilityAsync(name: string, param: Record<string, Object>,
    pageLoader: UIExtensionContentSession):
    Promise<insightIntent.ExecuteResult> {
    this.isOnExecuteInUIExtensionAbilityAsync = false;
    return new Promise<insightIntent.ExecuteResult>((
      resolve: (a: insightIntent.ExecuteResult) => void,
      reject: (err: Error) => void): void => {
    });
  }

  onExecuteInServiceExtensionAbility(name: string, param: Record<string, Object>):
    insightIntent.ExecuteResult {
    let ret: insightIntent.ExecuteResult = {};
    return ret;
  }

  onExecuteInServiceExtensionAbilityAsync(name: string, param: Record<string, Object>):
    Promise<insightIntent.ExecuteResult> {
    this.isOnExecuteInServiceExtensionAbilityAsync = false;
    return new Promise<insightIntent.ExecuteResult>((
      resolve: (a: insightIntent.ExecuteResult) => void,
      reject: (err: Error) => void): void => {
    });
  }
}