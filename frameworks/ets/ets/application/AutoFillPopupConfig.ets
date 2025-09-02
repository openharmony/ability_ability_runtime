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

export default interface AutoFillPopupConfig {
  popupSize?: PopupSize;
  placement?: PopupPlacement;
}
export interface PopupSize {
  width: double;
  height: double;
}
export enum PopupPlacement {
  LEFT = 0,
  RIGHT = 1,
  TOP = 2,
  BOTTOM = 3,
  TOP_LEFT = 4,
  TOP_RIGHT = 5,
  BOTTOM_LEFT = 6,
  BOTTOM_RIGHT = 7,
  LEFT_TOP = 8,
  LEFT_BOTTOM = 9,
  RIGHT_TOP = 10,
  RIGHT_BOTTOM = 11,
  NONE = 12
}

class AutoFillPopupConfigImpl implements AutoFillPopupConfig {
  public popupSize?: PopupSize;
  public placement?: PopupPlacement;
}
class PopupSizeImpl implements PopupSize {
  public width: double;
  public height: double;
}