/**
 * @tc.name: GenerateUid_0100
 * @tc.desc: test GenerateUid
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerEighthTest, GenerateUid_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0100 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    std::unordered_set<int32_t> assignedUids = {20200001, 20200002, 20200003};
    int32_t beginId = 1;
    int32_t endId = 10;
    int32_t userId = 101;
    int32_t uid = 0;
    std::unordered_map<int32_t, int32_t> lastIsolationIdMap = {{101, 3}, {102, 4}};
    int32_t res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200004);
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0100 end");
}
 
/**
 * @tc.name: GenerateUid_0200
 * @tc.desc: test GenerateUid
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerEighthTest, GenerateUid_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0200 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    std::unordered_set<int32_t> assignedUids = {20200001, 20200002, 20200004, 20200005};
    int32_t beginId = 1;
    int32_t endId = 5;
    int32_t userId = 101;
    int32_t uid = 0;
    std::unordered_map<int32_t, int32_t> lastIsolationIdMap = {{101, 5}, {102, 4}};
    int32_t res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200003);
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0200 end");
}
 
/**
 * @tc.name: GenerateUid_0300
 * @tc.desc: test GenerateUid
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerEighthTest, GenerateUid_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0300 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    std::unordered_set<int32_t> assignedUids = {20200001, 20200002, 20200003, 20200004, 20200005};
    int32_t beginId = 1;
    int32_t endId = 5;
    int32_t userId = 101;
    int32_t uid = 0;
    std::unordered_map<int32_t, int32_t> lastIsolationIdMap = {{101, 5}, {102, 4}};
    int32_t res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, false);
    EXPECT_EQ(uid, 0);
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0300 end");
}
 
/**
 * @tc.name: GenerateUid_0400
 * @tc.desc: test GenerateUid
 * @tc.type: FUNC
 */
HWTEST_F(AppMgrServiceInnerEighthTest, GenerateUid_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0400 start");
    auto appMgrServiceInner = std::make_shared<AppMgrServiceInner>();
    ASSERT_NE(appMgrServiceInner, nullptr);
    std::unordered_set<int32_t> assignedUids = {20200001, 20200002};
    int32_t beginId = 1;
    int32_t endId = 5;
    int32_t userId = 101;
    int32_t uid = 0;
    std::unordered_map<int32_t, int32_t> lastIsolationIdMap = {{101, 2}, {102, 4}};
    int32_t res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200003);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200004);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200005);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, false);
    EXPECT_EQ(uid, 20200005);
    assignedUids.erase(20200002);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20200002);
    userId = 102;
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20400005);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20400001);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20400002);
    userId = 103;
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20600002);
    res = appMgrServiceInner->GenerateUid(assignedUids, beginId, endId, userId, uid, lastIsolationIdMap);
    EXPECT_EQ(res, true);
    EXPECT_EQ(uid, 20600003);
    TAG_LOGI(AAFwkTag::TEST, "GenerateUid_0400 end");
}