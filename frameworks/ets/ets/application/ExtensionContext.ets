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

import Context from 'application.Context'
import { ExtensionAbilityInfo }  from 'bundleManager.ExtensionAbilityInfo'
import { Configuration } from '@ohos.app.ability.Configuration'
import { HapModuleInfo } from 'bundleManager.HapModuleInfo'

export default class ExtensionContext extends Context {
  static {
    loadLibrary("extension_context_ani_kit.z");
  }

  extensionAbilityInfo!: ExtensionAbilityInfo;
  config!: Configuration;
  currentHapModuleInfo!: HapModuleInfo;

  private static native nativeTransferStatic(input: ESValue, type: string): Object;
  private static native nativeTransferDynamic(input: Object): ESValue;
  private static contextType: string = 'ExtensionContext';

  static transferStatic(input: Any): Object {
    let type: string = '';
    try {
      type = ESValue.wrap(input).getProperty('__context_impl__').getProperty('contextType').toString();
    } catch (err) {
      console.log('transferStatic err: ' + err.toString());
    }
    console.log('transferStatic type: ' + type);
    return ExtensionContext.nativeTransferStatic(ESValue.wrap(input), type);
  }

  static transferDynamic(input: Object): Any {
    return ExtensionContext.nativeTransferDynamic(input).unwrap();
  }
}