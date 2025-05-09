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

import Want from '@ohos.app.ability.Want';
import wantConstant from '@ohos.app.ability.wantConstant';

namespace insightIntent {

  export enum ExecuteMode {
    UI_ABILITY_FOREGROUND = 0,
    UI_ABILITY_BACKGROUND = 1,
    UI_EXTENSION_ABILITY = 2,
    SERVICE_EXTENSION_ABILITY = 3,
  }

  export interface ExecuteResult {
    code: number;
    result?: Record<string, Object>;
    uris?: Array<string>;
    flags?: number;
  }

  export class ExecuteResultInner implements ExecuteResult{
    code: number;
    result?: Record<string, Object>;
    uris?: Array<string>;
    flags?: number;
  }
}

export default insightIntent;