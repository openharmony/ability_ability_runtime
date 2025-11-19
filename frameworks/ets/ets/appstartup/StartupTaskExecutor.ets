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

import StartupTask from '../@ohos.app.appstartup.StartupTask';
import type common from '@ohos.app.ability.common';

export default class StartupTaskExecutor {
  static {
    loadLibraryWithPermissionCheck("ability_stage_ani.z", "appstartup.StartupTaskExecutor");
  }

  private native nativeOnTaskSuccess(callback: long, result?: Any): void;
  private native nativeOnTaskFailure(callback: long, error: string): void;
  
  asyncPushTask(startup: StartupTask, context: common.AbilityStageContext, callback: long): void {
    const executeAsync = async (startup: StartupTask, context: common.AbilityStageContext): Promise<Any> => {
      return await startup.init(context);
    };

    const task = new taskpool.Task(executeAsync, startup, context);
    taskpool.execute(task).then((result: Any) => {
      this.nativeOnTaskSuccess(callback, result);
    }).catch((error: Error) => {
      this.nativeOnTaskFailure(callback, error.message);
    });
  }

  executeStartupTaskOnMainThread(startup: StartupTask, context: common.AbilityStageContext, 
    callback: long): void {
    startup.init(context).then((result: Any) => {
      this.nativeOnTaskSuccess(callback, result);
    }).catch((error: Error) => {
      this.nativeOnTaskFailure(callback, error.message);
    });
  }
}