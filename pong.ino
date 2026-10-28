#include <Adafruit_GFX.h>    
#include <Adafruit_ST7789.h> 
#include <SPI.h>

// --- 1. PINS ---
#define TFT_MOSI 19
#define TFT_SCLK 21
#define TFT_CS    2
#define TFT_DC    4
#define TFT_RST   3
#define TFT_BL    5

// --- 2. CONTROLS ---
#define BTN_UP    7
#define BTN_DOWN  15
#define BTN_A     23 // Right Paddle Up
#define BTN_B     22 // Right Paddle Down

// --- 3. GAME SETTINGS ---
#define GAME_WIDTH  160
#define GAME_HEIGHT 127

#define PADDLE_H    20 
#define PADDLE_W    3
#define BALL_SIZE   3
#define PADDLE_SPEED 3

// Colors
#define BLACK   0x0000
#define WHITE   0xFFFF
#define RED     0xF800
#define GREEN   0x07E0

// Driver (Software SPI)
Adafruit_ST7789 tft = Adafruit_ST7789(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);

// Game Variables
int ballX = GAME_WIDTH / 2;
int ballY = GAME_HEIGHT / 2;
int ballDirX = 2;
int ballDirY = 2;

int paddle1Y = (GAME_HEIGHT - PADDLE_H) / 2;
int paddle2Y = (GAME_HEIGHT - PADDLE_H) / 2;

int oldBallX, oldBallY;
int oldPaddle1Y, oldPaddle2Y;
int score1 = 0;
int score2 = 0;

// Optimization State
bool ballWasInScoreZone = false;

void setup() {
  Serial.begin(115200);
  pinMode(TFT_BL, OUTPUT);
  digitalWrite(TFT_BL, HIGH);

  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_A, INPUT_PULLUP);
  pinMode(BTN_B, INPUT_PULLUP);

  // Init Full Canvas
  tft.init(240, 320); 
  tft.setRotation(1);     
  tft.invertDisplay(false); 
  
  // Clean Wipe
  tft.fillRect(0, 0, 240, 320, ST77XX_BLACK);

  // Initial Draw
  drawField();
  drawScore();
  
  // Paddles
  tft.fillRect(0, paddle1Y, PADDLE_W, PADDLE_H, WHITE);
  tft.fillRect(GAME_WIDTH - PADDLE_W, paddle2Y, PADDLE_W, PADDLE_H, WHITE);
}

void loop() {
  // --- INPUT ---
  if (!digitalRead(BTN_UP) && paddle1Y > 2) paddle1Y -= PADDLE_SPEED;
  if (!digitalRead(BTN_DOWN) && paddle1Y < GAME_HEIGHT - PADDLE_H - 2) paddle1Y += PADDLE_SPEED;
  
  if (!digitalRead(BTN_A) && paddle2Y > 2) paddle2Y -= PADDLE_SPEED;
  if (!digitalRead(BTN_B) && paddle2Y < GAME_HEIGHT - PADDLE_H - 2) paddle2Y += PADDLE_SPEED;

  // --- PHYSICS ---
  oldBallX = ballX;
  oldBallY = ballY;
  ballX += ballDirX;
  ballY += ballDirY;

  // Bounce
  if (ballY <= 2 || ballY >= GAME_HEIGHT - BALL_SIZE - 2) ballDirY = -ballDirY;

  // Paddles
  if (ballX <= PADDLE_W && ballY + BALL_SIZE >= paddle1Y && ballY <= paddle1Y + PADDLE_H) {
    ballDirX = abs(ballDirX);
    ballX = PADDLE_W + 1;
  }
  if (ballX >= GAME_WIDTH - PADDLE_W - BALL_SIZE && ballY + BALL_SIZE >= paddle2Y && ballY <= paddle2Y + PADDLE_H) {
    ballDirX = -abs(ballDirX);
    ballX = GAME_WIDTH - PADDLE_W - BALL_SIZE - 1;
  }

  // Score
  if (ballX < 0) { score2++; resetBall(); }
  if (ballX > GAME_WIDTH) { score1++; resetBall(); }

  // --- DRAWING ---
  
  // 1. Erase Old Ball
  tft.fillRect(oldBallX, oldBallY, BALL_SIZE, BALL_SIZE, BLACK);

  // 2. LOGIC: SCORE REPAIR
  // Check if ball is currently in the top 25 pixels
  bool ballInScoreZone = (ballY < 25);

  // We ONLY redraw the text when the ball LEAVES the zone.
  // This keeps the game fast while the ball is moving through the text.
  if (ballWasInScoreZone && !ballInScoreZone) {
    drawScore(); 
    // Also repair top green line just in case
    tft.drawFastHLine(0, 0, GAME_WIDTH, GREEN);
  }
  
  // Update state for next loop
  ballWasInScoreZone = ballInScoreZone;

  // Repair Net (only if ball passed through middle)
  if (abs(oldBallX - GAME_WIDTH/2) < 5) drawNet();
  
  // Repair Bottom Green Line
  if (oldBallY >= GAME_HEIGHT - 4) tft.drawFastHLine(0, GAME_HEIGHT-1, GAME_WIDTH, GREEN);

  // 3. Update Paddles
  if (oldPaddle1Y != paddle1Y) {
    tft.fillRect(0, oldPaddle1Y, PADDLE_W, PADDLE_H, BLACK);
    tft.fillRect(0, paddle1Y, PADDLE_W, PADDLE_H, RED);
  }
  
  if (oldPaddle2Y != paddle2Y) {
    tft.fillRect(GAME_WIDTH - PADDLE_W, oldPaddle2Y, PADDLE_W, PADDLE_H, BLACK);
    tft.fillRect(GAME_WIDTH - PADDLE_W, paddle2Y, PADDLE_W, PADDLE_H, GREEN);
  }

  // 4. Draw New Ball
  tft.fillRect(ballX, ballY, BALL_SIZE, BALL_SIZE, WHITE);

  oldPaddle1Y = paddle1Y;
  oldPaddle2Y = paddle2Y;
  
  delay(15); 
}

// --- HELPERS ---

void drawField() {
  tft.drawFastHLine(0, 0, GAME_WIDTH, GREEN);
  tft.drawFastHLine(0, GAME_HEIGHT-1, GAME_WIDTH, GREEN);
  drawNet();
}

void drawNet() {
  for (int i = 0; i < GAME_HEIGHT; i += 8) {
    tft.fillRect(GAME_WIDTH / 2 - 1, i, 2, 4, 0x5AEB);
  }
}

void drawScore() {
  tft.setTextSize(2);
  tft.setTextColor(WHITE, BLACK);
  
  // Left Score (Centered roughly on left half)
  tft.setCursor(55, 4);
  tft.print(score1);

  // Right Score (Centered roughly on right half)
  tft.setCursor(95, 4);
  tft.print(score2);
}

void updateScore() {
  // WIDENED wipe area: X=20 to X=140 (Width 120)
  // This prevents "distortion"/garbage when right score goes from 9 to 10.
  tft.fillRect(20, 0, 120, 22, BLACK);
  drawField(); 
  drawScore();
}

void resetBall() {
  ballX = GAME_WIDTH / 2;
  ballY = GAME_HEIGHT / 2;
  ballDirX = -ballDirX;
  ballDirY = 2;
  
  updateScore(); 
  
  // Flash
  tft.drawFastHLine(0, 0, GAME_WIDTH, WHITE);
  tft.drawFastHLine(0, GAME_HEIGHT-1, GAME_WIDTH, WHITE);
  delay(100);
  drawField(); 
  
  // Redraw paddles
  tft.fillRect(0, paddle1Y, PADDLE_W, PADDLE_H, RED);
  tft.fillRect(GAME_WIDTH - PADDLE_W, paddle2Y, PADDLE_W, PADDLE_H, GREEN);
  
  delay(500);
}