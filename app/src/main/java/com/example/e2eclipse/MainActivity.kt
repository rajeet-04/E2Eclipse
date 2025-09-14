package com.example.e2eclipse

import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.*
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

// --- DATA MODELS FOR COMMUNICATION ---
data class WebSocketMessage(val type: String, val roomId: String, val payload: Payload)
data class Payload(val message: String? = null, val targetId: String? = null, val data: Any? = null)
data class Message(val id: String, val senderId: String, val text: String, val isMine: Boolean, val type: MessageType)
enum class MessageType { USER_MESSAGE, SYSTEM_MESSAGE }
enum class Screen { HOME, JOINING, CHAT }

// --- UI STATE ---
data class ChatUiState(
    val screen: Screen = Screen.HOME,
    val roomId: String = "",
    val userId: String = "",
    val messages: List<Message> = emptyList(),
    val isConnected: Boolean = false,
    val error: String? = null,
    val userCount: Int = 0,
    val networkTestResult: String? = null
)

// --- CRYPTOGRAPHY MANAGER ---
class CryptoManager {
    private var ecdhKeyPair: KeyPair? = null
    private var groupKey: SecretKey? = null

    init {
        generateEcdhKeyPair()
    }

    private fun generateEcdhKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"))
        ecdhKeyPair = keyPairGenerator.generateKeyPair()
    }

    fun getPublicKeyBase64(): String {
        return Base64.encodeToString(ecdhKeyPair?.public?.encoded, Base64.NO_WRAP)
    }

    fun generateSharedSecret(peerPublicKeyBase64: String): SecretKey {
        val keyFactory = KeyFactory.getInstance("EC")
        val publicKeyBytes = Base64.decode(peerPublicKeyBase64, Base64.DEFAULT)
        val peerPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(ecdhKeyPair?.private)
        keyAgreement.doPhase(peerPublicKey, true)

        val sharedSecret = keyAgreement.generateSecret()
        return SecretKeySpec(sharedSecret, 0, 32, "AES")
    }

    fun generateGroupKey() {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        groupKey = SecretKeySpec(key, "AES")
    }

    fun getGroupKeyBase64(): String? {
        return groupKey?.let { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
    }

    fun setGroupKey(keyBase64: String) {
        val decodedKey = Base64.decode(keyBase64, Base64.DEFAULT)
        groupKey = SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
    }

    fun encryptWithGroupKey(data: String): Pair<String, String>? {
        groupKey ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, groupKey, GCMParameterSpec(128, iv))
        val encryptedData = cipher.doFinal(data.toByteArray())
        val ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        val encryptedDataBase64 = Base64.encodeToString(encryptedData, Base64.NO_WRAP)
        return Pair(ivBase64, encryptedDataBase64)
    }

    fun decryptWithGroupKey(ivBase64: String, encryptedDataBase64: String): String? {
        groupKey ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = Base64.decode(ivBase64, Base64.DEFAULT)
            val encryptedData = Base64.decode(encryptedDataBase64, Base64.DEFAULT)
            cipher.init(Cipher.DECRYPT_MODE, groupKey, GCMParameterSpec(128, iv))
            String(cipher.doFinal(encryptedData))
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun encryptWithSharedKey(data: String, sharedKey: SecretKey): Pair<String, String> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, sharedKey, GCMParameterSpec(128, iv))
        val encryptedData = cipher.doFinal(data.toByteArray())
        val ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        val encryptedDataBase64 = Base64.encodeToString(encryptedData, Base64.NO_WRAP)
        return Pair(ivBase64, encryptedDataBase64)
    }

    fun decryptWithSharedKey(ivBase64: String, encryptedDataBase64: String, sharedKey: SecretKey): String? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = Base64.decode(ivBase64, Base64.DEFAULT)
            val encryptedData = Base64.decode(encryptedDataBase64, Base64.DEFAULT)
            cipher.init(Cipher.DECRYPT_MODE, sharedKey, GCMParameterSpec(128, iv))
            String(cipher.doFinal(encryptedData))
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}

// --- VIEWMODEL ---
class ChatViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(ChatUiState())
    val uiState = _uiState.asStateFlow()

    private val gson = Gson()
    private val cryptoManager = CryptoManager()
    private var webSocketClient: WebSocket? = null
    private val okHttpClient = OkHttpClient()

    private fun addMessage(message: Message) {
        _uiState.value = _uiState.value.copy(messages = _uiState.value.messages + message)
    }

    fun createRoom() {
        val roomId = (1000..9999).random().toString()
        _uiState.value = _uiState.value.copy(roomId = roomId, screen = Screen.JOINING)
        connect(roomId, isCreator = true)
    }

    fun joinRoom(roomId: String) {
        if (roomId.isBlank()) {
            _uiState.value = _uiState.value.copy(error = "Room ID cannot be empty")
            return
        }
        _uiState.value = _uiState.value.copy(roomId = roomId, screen = Screen.JOINING)
        connect(roomId, isCreator = false)
    }

    fun leaveRoom() {
        webSocketClient?.close(1000, "User left")
        webSocketClient = null
        _uiState.value = ChatUiState()
    }

    private fun connect(roomId: String, isCreator: Boolean) {
        val serverIp = "131.163.96.176" // IMPORTANT: YOUR SERVER IP
        val request = Request.Builder().url("ws://$serverIp:8080").build()
        Log.d("ChatViewModel", "Attempting to connect to ws://$serverIp:8080")

        webSocketClient = okHttpClient.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                viewModelScope.launch(Dispatchers.Main) {
                    Log.d("ChatViewModel", "Connection OPEN")
                    _uiState.value = _uiState.value.copy(isConnected = true, error = null)
                    val type = if (isCreator) "create_room" else "join_room"
                    webSocket.send(gson.toJson(mapOf("type" to type, "roomId" to roomId)))
                }
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                viewModelScope.launch(Dispatchers.Main) {
                    Log.d("ChatViewModel", "MESSAGE received: $text")
                    handleSocketMessage(text)
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                viewModelScope.launch(Dispatchers.Main) {
                    Log.d("ChatViewModel", "Connection CLOSING: $reason")
                    addMessage(Message(Random.nextInt().toString(), "System", "Disconnected: $reason", false, MessageType.SYSTEM_MESSAGE))
                    _uiState.value = _uiState.value.copy(isConnected = false, userCount = 0)
                }
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                viewModelScope.launch(Dispatchers.Main) {
                    Log.e("ChatViewModel", "Connection FAILURE", t)
                    _uiState.value = _uiState.value.copy(isConnected = false, error = "Connection failed: ${t.message}", screen = Screen.HOME)
                }
            }
        })
    }

    fun testNetwork() {
        _uiState.value = _uiState.value.copy(networkTestResult = "Testing...")
        viewModelScope.launch(Dispatchers.IO) {
            val testRequest = Request.Builder().url("https://www.google.com").build()
            try {
                okHttpClient.newCall(testRequest).execute().use { response ->
                    val result = if (response.isSuccessful) "SUCCESS: Connected to Google.com" else "FAIL: Code ${response.code}"
                    launch(Dispatchers.Main) {
                        _uiState.value = _uiState.value.copy(networkTestResult = result)
                    }
                }
            } catch (e: Exception) {
                launch(Dispatchers.Main) {
                    _uiState.value = _uiState.value.copy(networkTestResult = "ERROR: ${e.message}")
                }
            }
        }
    }

    private fun handleSocketMessage(text: String) {
        val type = object : TypeToken<Map<String, Any>>() {}.type
        val messageMap: Map<String, Any> = gson.fromJson(text, type)

        when (messageMap["type"]) {
            "joined_room" -> {
                val payload = messageMap["payload"] as Map<*, *>
                val userId = payload["userId"] as String
                val otherUsers = payload["otherUsers"] as List<String>
                _uiState.value = _uiState.value.copy(userId = userId, screen = Screen.CHAT, userCount = otherUsers.size + 1)
                addMessage(Message(Random.nextInt().toString(), "System", "You have joined the room. Welcome!", false, MessageType.SYSTEM_MESSAGE))

                if (otherUsers.isNotEmpty()) {
                    val targetId = otherUsers.first()
                    val keyExchangeOffer = mapOf(
                        "type" to "key_exchange_offer",
                        "publicKey" to cryptoManager.getPublicKeyBase64()
                    )
                    relayMessage(targetId, keyExchangeOffer)
                } else {
                    cryptoManager.generateGroupKey()
                    addMessage(Message(Random.nextInt().toString(), "System", "You created the room. A new secure key has been generated.", false, MessageType.SYSTEM_MESSAGE))
                }
            }
            "new_user" -> {
                val payload = messageMap["payload"] as Map<*, *>
                val newUser = payload["userId"] as String
                _uiState.value = _uiState.value.copy(userCount = _uiState.value.userCount + 1)
                addMessage(Message(Random.nextInt().toString(), "System", "User ${newUser.substring(0, 6)}... has joined.", false, MessageType.SYSTEM_MESSAGE))
            }
            "user_left" -> {
                val payload = messageMap["payload"] as Map<*, *>
                val leftUser = payload["userId"] as String
                _uiState.value = _uiState.value.copy(userCount = _uiState.value.userCount - 1)
                addMessage(Message(Random.nextInt().toString(), "System", "User ${leftUser.substring(0, 6)}... has left.", false, MessageType.SYSTEM_MESSAGE))
            }
            "peer_message" -> {
                val payload = messageMap["payload"] as Map<*, *>
                val senderId = payload["senderId"] as String
                val data = payload["data"] as Map<*, *>
                handlePeerMessage(senderId, data)
            }
            "message_broadcast" -> {
                val payload = messageMap["payload"] as Map<*, *>
                val senderId = payload["senderId"] as String
                val messageJson = payload["message"] as String
                val messageData: Map<String, String> = gson.fromJson(messageJson, object: TypeToken<Map<String, String>>(){}.type)

                val decryptedText = cryptoManager.decryptWithGroupKey(messageData["iv"]!!, messageData["content"]!!)
                if (decryptedText != null) {
                    val decodedMessage: Map<String, String> = gson.fromJson(decryptedText, object: TypeToken<Map<String, String>>(){}.type)
                    if (decodedMessage["type"] == "group_key_update") {
                        cryptoManager.setGroupKey(decodedMessage["key"]!!)
                        addMessage(Message(Random.nextInt().toString(), "System", "Group key has been updated for security.", false, MessageType.SYSTEM_MESSAGE))
                    } else {
                        addMessage(Message(Random.nextInt().toString(), senderId, decodedMessage["text"]!!, false, MessageType.USER_MESSAGE))
                    }
                }
            }
        }
    }

    private fun handlePeerMessage(senderId: String, data: Map<*, *>) {
        when (data["type"]) {
            "key_exchange_offer" -> {
                val peerPublicKey = data["publicKey"] as String
                val sharedSecret = cryptoManager.generateSharedSecret(peerPublicKey)

                val oldKey = cryptoManager.getGroupKeyBase64()
                cryptoManager.generateGroupKey()
                addMessage(Message(Random.nextInt().toString(), "System", "A new user joined. Regenerating group key...", false, MessageType.SYSTEM_MESSAGE))

                val newGroupKeyBase64 = cryptoManager.getGroupKeyBase64()!!
                val (iv, encryptedKey) = cryptoManager.encryptWithSharedKey(newGroupKeyBase64, sharedSecret)

                val keyExchangeAnswer = mapOf(
                    "type" to "key_exchange_answer",
                    "iv" to iv,
                    "encryptedKey" to encryptedKey,
                    "senderPublicKey" to cryptoManager.getPublicKeyBase64()
                )
                relayMessage(senderId, keyExchangeAnswer)

                if (oldKey != null) {
                    val oldCrypto = CryptoManager().apply { setGroupKey(oldKey) }
                    val keyUpdateMessage = mapOf("type" to "group_key_update", "key" to newGroupKeyBase64)
                    val encryptedUpdate = oldCrypto.encryptWithGroupKey(gson.toJson(keyUpdateMessage))
                    if(encryptedUpdate != null) {
                        broadcastMessage(encryptedUpdate.first, encryptedUpdate.second)
                    }
                }
            }
            "key_exchange_answer" -> {
                val iv = data["iv"] as String
                val encryptedKey = data["encryptedKey"] as String
                val senderPublicKey = data["senderPublicKey"] as String

                val sharedSecret = cryptoManager.generateSharedSecret(senderPublicKey)
                val groupKey = cryptoManager.decryptWithSharedKey(iv, encryptedKey, sharedSecret)

                if (groupKey != null) {
                    cryptoManager.setGroupKey(groupKey)
                    addMessage(Message(Random.nextInt().toString(), "System", "Secure key received. You are now in the chat.", false, MessageType.SYSTEM_MESSAGE))
                } else {
                    addMessage(Message(Random.nextInt().toString(), "System", "Key exchange failed. Please rejoin.", false, MessageType.SYSTEM_MESSAGE))
                    leaveRoom()
                }
            }
        }
    }

    private fun relayMessage(targetId: String, data: Any) {
        val message = WebSocketMessage(
            type = "relay_message",
            roomId = uiState.value.roomId,
            payload = Payload(targetId = targetId, data = data)
        )
        webSocketClient?.send(gson.toJson(message))
    }

    private fun broadcastMessage(iv: String, content: String) {
        val messagePayload = mapOf("iv" to iv, "content" to content)
        val message = WebSocketMessage(
            type = "broadcast_message",
            roomId = uiState.value.roomId,
            payload = Payload(message = gson.toJson(messagePayload))
        )
        webSocketClient?.send(gson.toJson(message))
    }

    fun sendMessage(text: String) {
        if (text.isBlank() || !uiState.value.isConnected) return

        val messageContent = mapOf("type" to "user_message", "text" to text)
        val encrypted = cryptoManager.encryptWithGroupKey(gson.toJson(messageContent))

        if (encrypted != null) {
            val (iv, content) = encrypted
            broadcastMessage(iv, content)
            addMessage(Message(Random.nextInt().toString(), uiState.value.userId, text, true, MessageType.USER_MESSAGE))
        }
    }
}

// --- MAIN ACTIVITY & UI ---
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        setContent {
            AppTheme {
                ChatScreen()
            }
        }
    }
}

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF7E57C2), // A slightly deeper purple
            secondary = Color(0xFF26A69A), // A calmer teal
            background = Color(0xFF121212),
            surface = Color(0xFF1E1E1E),
            onPrimary = Color.White,
            onSecondary = Color.White,
            onBackground = Color(0xFFE0E0E0), // Lighter text for less contrast
            onSurface = Color(0xFFE0E0E0)
        ),
        typography = Typography(
            bodyLarge = LocalTextStyle.current.copy(fontSize = 17.sp) // Slightly larger body text
        ),
        content = content
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(viewModel: ChatViewModel = androidx.lifecycle.viewmodel.compose.viewModel()) {
    val uiState by viewModel.uiState.collectAsState()
    val listState = rememberLazyListState()

    LaunchedEffect(uiState.messages.size) {
        if (uiState.messages.isNotEmpty()) {
            listState.animateScrollToItem(uiState.messages.size - 1)
        }
    }

    val backgroundBrush = Brush.verticalGradient(
        colors = listOf(
            Color(0xFF222222),
            Color(0xFF121212)
        )
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                        Text(if (uiState.roomId.isNotEmpty()) "Room: ${uiState.roomId}" else "", fontWeight = FontWeight.Bold)
                        if (uiState.screen == Screen.CHAT) {
                            Text(
                                text = if (uiState.isConnected) "${uiState.userCount} users online" else "Disconnected",
                                fontSize = 12.sp,
                                color = if (uiState.isConnected) Color(0xFF4CAF50) else Color(0xFFF44336)
                            )
                        }
                    }
                },
                navigationIcon = {
                    if (uiState.screen != Screen.HOME) {
                        IconButton(onClick = { viewModel.leaveRoom() }) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Leave Room")
                        }
                    } else {
                        Spacer(modifier = Modifier.width(48.dp)) // Placeholder to balance title
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = MaterialTheme.colorScheme.onSurface
                ),
                modifier = Modifier.background(Color.Transparent)
            )
        },
        bottomBar = {
            if (uiState.screen == Screen.CHAT) {
                MessageInput(onSend = { viewModel.sendMessage(it) })
            }
        },
        containerColor = Color.Transparent,
        modifier = Modifier.background(brush = backgroundBrush)
    ) { paddingValues ->
        Box(modifier = Modifier.padding(paddingValues).fillMaxSize()) {
            when (uiState.screen) {
                Screen.HOME -> HomeScreen(
                    onCreateRoom = { viewModel.createRoom() },
                    onJoinRoom = { viewModel.joinRoom(it) },
                    onTestNetwork = { viewModel.testNetwork() },
                    networkTestResult = uiState.networkTestResult
                )
                Screen.JOINING -> JoiningScreen(roomId = uiState.roomId)
                Screen.CHAT -> MessageList(messages = uiState.messages, listState = listState)
            }

            uiState.error?.let {
                Snackbar(
                    modifier = Modifier.padding(16.dp).align(Alignment.BottomCenter),
                    action = { Button(onClick = {}) { Text("OK") } }
                ) {
                    Text(it)
                }
            }
        }
    }
}

@Composable
fun HomeScreen(
    onCreateRoom: () -> Unit,
    onJoinRoom: (String) -> Unit,
    onTestNetwork: () -> Unit,
    networkTestResult: String?
) {
    var roomIdInput by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(horizontal = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Image(
            painter = painterResource(id = R.drawable.ic_logo),
            contentDescription = "E2Eclipse Logo",
            modifier = Modifier.size(120.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text("E2Eclipse Chat", fontSize = 28.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
        Text("Secure. Anonymous. Disposable.", fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground)
        Spacer(modifier = Modifier.height(48.dp))
        Button(onClick = onCreateRoom, modifier = Modifier.fillMaxWidth().height(50.dp)) {
            Text("Create Secure Room", fontSize = 16.sp)
        }
        Spacer(modifier = Modifier.height(24.dp))
        OutlinedTextField(
            value = roomIdInput,
            onValueChange = { roomIdInput = it },
            label = { Text("Enter Room ID to Join") },
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(modifier = Modifier.height(12.dp))
        Button(onClick = { onJoinRoom(roomIdInput) }, modifier = Modifier.fillMaxWidth().height(50.dp)) {
            Text("Join Room", fontSize = 16.sp)
        }
        Spacer(modifier = Modifier.height(32.dp))
        OutlinedButton(onClick = onTestNetwork, modifier = Modifier.fillMaxWidth()) {
            Text("Test Internet Connection")
        }
        networkTestResult?.let {
            Spacer(modifier = Modifier.height(12.dp))
            Text(it, color = if(it.startsWith("SUCCESS")) Color.Green else MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
fun JoiningScreen(roomId: String) {
    val clipboardManager = LocalClipboardManager.current
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Connecting...", fontSize = 22.sp)
        Spacer(modifier = Modifier.height(16.dp))
        CircularProgressIndicator()
        Spacer(modifier = Modifier.height(24.dp))
        Text("Share this Room ID with others:", fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground)
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.surface)
                .padding(horizontal = 24.dp, vertical = 16.dp)
                .clickable { clipboardManager.setText(AnnotatedString(roomId)) }
        ) {
            Text(roomId, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.secondary)
            Spacer(modifier = Modifier.width(16.dp))
            Icon(Icons.Default.ContentCopy, contentDescription = "Copy Room ID")
        }
    }
}

@OptIn(ExperimentalAnimationApi::class)
@Composable
fun MessageList(messages: List<Message>, listState: androidx.compose.foundation.lazy.LazyListState) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 16.dp)
    ) {
        itemsIndexed(messages, key = { _, message -> message.id }) { index, message ->
            AnimatedVisibility(
                visible = true, // This can be tied to a state to animate item removal
                enter = slideInHorizontally(
                    initialOffsetX = { if (message.isMine) 300 else -300 },
                    animationSpec = tween(durationMillis = 300, delayMillis = index * 50)
                ) + fadeIn(animationSpec = tween(durationMillis = 200, delayMillis = index * 50)),
                exit = fadeOut(animationSpec = tween(150))
            ) {
                MessageBubble(message = message)
            }
        }
    }
}

@Composable
fun MessageBubble(message: Message) {
    val alignment = if (message.isMine) Alignment.CenterEnd else Alignment.CenterStart
    val bubbleColor = when {
        message.type == MessageType.SYSTEM_MESSAGE -> Color.Transparent
        message.isMine -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.surface
    }
    val textColor = when {
        message.type == MessageType.SYSTEM_MESSAGE -> Color.Gray
        message.isMine -> MaterialTheme.colorScheme.onPrimary
        else -> MaterialTheme.colorScheme.onSurface
    }
    val bubbleShape = if (message.isMine) {
        RoundedCornerShape(20.dp, 4.dp, 20.dp, 20.dp)
    } else {
        RoundedCornerShape(4.dp, 20.dp, 20.dp, 20.dp)
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp, horizontal = 8.dp),
        contentAlignment = alignment
    ) {
        if (message.type == MessageType.SYSTEM_MESSAGE) {
            Text(
                text = message.text,
                color = textColor,
                fontSize = 12.sp,
                modifier = Modifier.padding(vertical = 8.dp)
            )
        } else {
            Column(
                modifier = Modifier
                    .shadow(elevation = 4.dp, shape = bubbleShape)
                    .clip(bubbleShape)
                    .background(bubbleColor)
                    .padding(vertical = 10.dp, horizontal = 16.dp)
            ) {
                if (!message.isMine) {
                    Text(
                        text = "User ${message.senderId.substring(0, 6)}...",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.secondary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                }
                SelectionContainer {
                    Text(text = message.text, color = textColor)
                }
            }
        }
    }
}

@Composable
fun MessageInput(onSend: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding() // Respects system navigation gestures
            .padding(8.dp)
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .shadow(elevation = 8.dp, shape = RoundedCornerShape(26.dp)),
            shape = RoundedCornerShape(26.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextField(
                    value = text,
                    onValueChange = { text = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Type a secure message...") },
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = Color.Transparent,
                        unfocusedContainerColor = Color.Transparent,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent
                    )
                )
                IconButton(
                    onClick = {
                        if (text.isNotBlank()) {
                            onSend(text)
                            text = ""
                        }
                    },
                    enabled = text.isNotBlank()
                ) {
                    Icon(
                        Icons.Default.Send,
                        contentDescription = "Send Message",
                        tint = if(text.isNotBlank()) MaterialTheme.colorScheme.primary else Color.Gray
                    )
                }
            }
        }
    }
}

