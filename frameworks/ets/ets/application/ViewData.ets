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

import PageNodeInfo from 'application.PageNodeInfo';
import AutoFillRect from 'application.AutoFillRect';

export default interface ViewData {
  bundleName: string;
  moduleName: string;
  abilityName: string;
  pageUrl: string;
  pageNodeInfos: Array<PageNodeInfo>;
  pageRect: AutoFillRect;
  isUserSelected: boolean;
  isOtherAccount: boolean;
}

class ViewDataImpl implements ViewData {
  public bundleName: string = '';
  public moduleName: string = '';
  public abilityName: string = '';
  public pageUrl: string = '';
  public pageNodeInfos: Array<PageNodeInfo> = [];
  public pageRect: AutoFillRect = {left: 0.0, top: 0.0, width: 0.0, height: 0.0};
  public isUserSelected: boolean;
  public isOtherAccount: boolean;
}