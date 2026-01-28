/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
import { AgentCard } from './@ohos.app.ability.AgentCard';

export default namespace agentManager {
  loadLibraryWithPermissionCheck("agent_manager_ani.z", "@ohos.app.ability.agentManager")

  export native function nativeGetAllAgentCards(): Array<AgentCard>;
  export native function nativeGetAgentCardsByBundleName(bundleName: string): Array<AgentCard>;
  export native function nativeGetAgentCardByAgentId(bundleName: string, agentId: string): AgentCard;

  export function getAllAgentCards(): Promise<Array<AgentCard>> {
    let p: Promise<Array<AgentCard>> = new Promise<Array<AgentCard>>(
      (res: (data: Array<AgentCard>) => void, rej: (error: Error) => void): void => {
      taskpool.execute((): Array<AgentCard> => {
        return agentManager.nativeGetAllAgentCards();
      }).then((e: Any) => {
        let cards: Array<AgentCard> = e as Array<AgentCard>;
        res(cards);
      }, (err: Error): void => {
        rej(err);
      });
    });
    return p;
  }

  export function getAgentCardsByBundleName(bundleName: string): Promise<Array<AgentCard>> {
    let p: Promise<Array<AgentCard>> = new Promise<Array<AgentCard>>(
      (res: (data: Array<AgentCard>) => void, rej: (error: Error) => void): void => {
      taskpool.execute((): Array<AgentCard> => {
        return agentManager.nativeGetAgentCardsByBundleName(bundleName);
      }).then((e: Any) => {
        let cards: Array<AgentCard> = e as Array<AgentCard>;
        res(cards);
      }, (err: Error): void => {
        rej(err);
      });
    });
    return p;
  }

  export function getAgentCardByAgentId(bundleName: string, agentId: string): Promise<AgentCard> {
    let p: Promise<AgentCard> = new Promise<AgentCard>(
      (res: (data: AgentCard) => void, rej: (error: Error) => void): void => {
      taskpool.execute((): AgentCard => {
        return agentManager.nativeGetAgentCardByAgentId(bundleName, agentId);
      }).then((e: Any) => {
        let card: AgentCard = e as AgentCard;
        res(card);
      }, (err: Error): void => {
        rej(err);
      });
    });
    return p;
  }
} // namespace agentManager
