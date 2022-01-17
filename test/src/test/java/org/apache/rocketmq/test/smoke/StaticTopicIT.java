package org.apache.rocketmq.test.smoke;

import org.apache.log4j.Logger;
import org.apache.rocketmq.common.MixAll;
import org.apache.rocketmq.common.message.MessageClientExt;
import org.apache.rocketmq.common.message.MessageConst;
import org.apache.rocketmq.common.message.MessageExt;
import org.apache.rocketmq.common.message.MessageQueue;
import org.apache.rocketmq.common.protocol.body.ClusterInfo;
import org.apache.rocketmq.common.rpc.ClientMetadata;
import org.apache.rocketmq.common.statictopic.TopicConfigAndQueueMapping;
import org.apache.rocketmq.common.statictopic.TopicQueueMappingOne;
import org.apache.rocketmq.common.statictopic.TopicQueueMappingUtils;
import org.apache.rocketmq.test.base.BaseConf;
import org.apache.rocketmq.test.client.rmq.RMQNormalConsumer;
import org.apache.rocketmq.test.client.rmq.RMQNormalProducer;
import org.apache.rocketmq.test.listener.rmq.concurrent.RMQNormalListener;
import org.apache.rocketmq.test.util.MQRandomUtils;
import org.apache.rocketmq.test.util.VerifyUtils;
import org.apache.rocketmq.tools.admin.DefaultMQAdminExt;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.common.truth.Truth.assertThat;
import static org.apache.rocketmq.common.statictopic.TopicQueueMappingUtils.getMappingDetailFromConfig;

@FixMethodOrder
public class StaticTopicIT extends BaseConf {

    private static Logger logger = Logger.getLogger(StaticTopicIT.class);
    private DefaultMQAdminExt defaultMQAdminExt;
    private ClientMetadata clientMetadata;

    @Before
    public void setUp() throws Exception {
        defaultMQAdminExt = getAdmin(nsAddr);
        waitBrokerRegistered(nsAddr, clusterName);
        clientMetadata = new ClientMetadata();
        defaultMQAdminExt.start();
        ClusterInfo clusterInfo  = defaultMQAdminExt.examineBrokerClusterInfo();
        if (clusterInfo == null
                || clusterInfo.getClusterAddrTable().isEmpty()) {
            throw new RuntimeException("The Cluster info is empty");
        }
        clientMetadata.refreshClusterInfo(clusterInfo);
    }

    public Map<String, TopicConfigAndQueueMapping> createStaticTopic(String topic, int queueNum, Set<String> targetBrokers) throws Exception {
        Map<String, TopicConfigAndQueueMapping> brokerConfigMap = defaultMQAdminExt.examineTopicConfigAll(clientMetadata, topic);
        Assert.assertTrue(brokerConfigMap.isEmpty());
        TopicQueueMappingUtils.createTopicConfigMapping(topic, queueNum, targetBrokers, new HashSet<>(), brokerConfigMap);
        Assert.assertEquals(2, brokerConfigMap.size());
        //If some succeed, and others fail, it will cause inconsistent data
        for (Map.Entry<String, TopicConfigAndQueueMapping> entry : brokerConfigMap.entrySet()) {
            String broker = entry.getKey();
            String addr = clientMetadata.findMasterBrokerAddr(broker);
            TopicConfigAndQueueMapping configMapping = entry.getValue();
            defaultMQAdminExt.createStaticTopic(addr, defaultMQAdminExt.getCreateTopicKey(), configMapping, configMapping.getMappingDetail(), false);
        }
        return brokerConfigMap;
    }

    @Test
    public void testCreateProduceConsumeStaticTopic() throws Exception {
        String topic = "static" + MQRandomUtils.getRandomTopic();
        RMQNormalProducer producer = getProducer(nsAddr, topic);
        RMQNormalConsumer consumer = getConsumer(nsAddr, topic, "*", new RMQNormalListener());

        int queueNum = 10;
        int msgEachQueue = 100;
        //create static topic
        Map<String, TopicConfigAndQueueMapping> localBrokerConfigMap = createStaticTopic(topic, queueNum, getBrokers());
        //check the static topic config
        {
            Map<String, TopicConfigAndQueueMapping> remoteBrokerConfigMap = defaultMQAdminExt.examineTopicConfigAll(clientMetadata, topic);
            Assert.assertEquals(2, remoteBrokerConfigMap.size());
            for (Map.Entry<String, TopicConfigAndQueueMapping> entry: remoteBrokerConfigMap.entrySet())  {
                String broker = entry.getKey();
                TopicConfigAndQueueMapping configMapping = entry.getValue();
                TopicConfigAndQueueMapping localConfigMapping = localBrokerConfigMap.get(broker);
                Assert.assertNotNull(localConfigMapping);
                Assert.assertEquals(configMapping, localConfigMapping);
            }
            TopicQueueMappingUtils.checkNameEpochNumConsistence(topic, remoteBrokerConfigMap);
            Map<Integer, TopicQueueMappingOne>  globalIdMap = TopicQueueMappingUtils.checkAndBuildMappingItems(new ArrayList<>(getMappingDetailFromConfig(remoteBrokerConfigMap.values())), false, true);
            Assert.assertEquals(queueNum, globalIdMap.size());
        }
        //check the route data
        List<MessageQueue> messageQueueList = producer.getMessageQueue();
        Assert.assertEquals(queueNum, messageQueueList.size());
        producer.setDebug(true);
        for (int i = 0; i < queueNum; i++) {
            MessageQueue messageQueue = messageQueueList.get(i);
            Assert.assertEquals(topic, messageQueue.getTopic());
            Assert.assertEquals(i, messageQueue.getQueueId());
            Assert.assertEquals(MixAll.LOGICAL_QUEUE_MOCK_BROKER_NAME, messageQueue.getBrokerName());
        }
        //send and consume the msg
        for(MessageQueue messageQueue: messageQueueList) {
            producer.send(msgEachQueue, messageQueue);
        }
        //leave the time to build the cq
        Thread.sleep(500);
        for(MessageQueue messageQueue: messageQueueList) {
            Assert.assertEquals(0, defaultMQAdminExt.minOffset(messageQueue));
            Assert.assertEquals(msgEachQueue, defaultMQAdminExt.maxOffset(messageQueue));
        }
        Assert.assertEquals(msgEachQueue * queueNum, producer.getAllOriginMsg().size());
        Assert.assertEquals(0, producer.getSendErrorMsg().size());

        consumer.getListener().waitForMessageConsume(producer.getAllMsgBody(), consumeTime);
        assertThat(VerifyUtils.getFilterdMessage(producer.getAllMsgBody(),
                consumer.getListener().getAllMsgBody()))
                .containsExactlyElementsIn(producer.getAllMsgBody());
        Map<Integer, List<MessageExt>> messagesByQueue = new HashMap<>();
        for (Object object : consumer.getListener().getAllOriginMsg()) {
            MessageExt messageExt = (MessageExt) object;
            if (!messagesByQueue.containsKey(messageExt.getQueueId())) {
                messagesByQueue.put(messageExt.getQueueId(), new ArrayList<>());
            }
            messagesByQueue.get(messageExt.getQueueId()).add(messageExt);
        }
        Assert.assertEquals(queueNum, messagesByQueue.size());
        for (int i = 0; i < queueNum; i++) {
            List<MessageExt> messageExts = messagesByQueue.get(i);
            Assert.assertEquals(msgEachQueue, messageExts.size());
            Collections.sort(messageExts, new Comparator<MessageExt>() {
                @Override
                public int compare(MessageExt o1, MessageExt o2) {
                    return (int) (o1.getQueueOffset() - o2.getQueueOffset());
                }
            });
            for (int j = 0; j < msgEachQueue; j++) {
                Assert.assertEquals(j, messageExts.get(j).getQueueOffset());
            }
        }
    }


    @After
    public void tearDown() {
        super.shutdown();
    }

}
